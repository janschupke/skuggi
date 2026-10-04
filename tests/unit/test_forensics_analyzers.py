"""L1: the pure-Python forensic analyzers, over realistic evidence bytes."""

from __future__ import annotations

import base64
import gzip
import hashlib
import os
from pathlib import Path

import pytest

from skuggi.forensics.analyzers import (
    encoding,
    entropy,
    hashes,
    hexview,
    keyed_decrypt,
    logparse,
    magic,
    strings,
)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- hashes -----------------------------------------------------------------


def test_hashes_match_hashlib(tmp_path: Path) -> None:
    body = b"the quick brown fox\n"
    p = _write(tmp_path, "a.txt", body)
    obs = {o.attributes["algorithm"]: o.value for o in hashes.analyze(p)}
    assert obs["sha256"] == hashlib.sha256(body).hexdigest()
    assert obs["md5"] == hashlib.md5(body).hexdigest()  # noqa: S324 -- forensic IOC value


def test_hashes_of_empty_file(tmp_path: Path) -> None:
    p = _write(tmp_path, "empty", b"")
    obs = {o.attributes["algorithm"]: o.value for o in hashes.analyze(p)}
    assert obs["sha256"] == hashlib.sha256(b"").hexdigest()


# --- strings ----------------------------------------------------------------


def test_strings_finds_ascii_with_offset(tmp_path: Path) -> None:
    # a printable run (with spaces + punctuation) embedded in binary noise
    data = b"\x00\x01" + b"GET /admin?x=1 HTTP/1.1" + b"\xff\x00"
    p = _write(tmp_path, "b.bin", data)
    found = [o for o in strings.analyze(p) if o.kind == "string"]
    values = [o.value for o in found]
    assert "GET /admin?x=1 HTTP/1.1" in values
    hit = next(o for o in found if o.value.startswith("GET"))
    assert hit.attributes["offset"] == hex(2)
    assert hit.attributes["encoding"] == "ascii"


def test_strings_finds_utf16le(tmp_path: Path) -> None:
    data = "C:\\Windows\\System32".encode("utf-16-le")
    p = _write(tmp_path, "w.bin", data)
    found = [o for o in strings.analyze(p) if o.kind == "string"]
    assert any(
        o.attributes["encoding"] == "utf-16le" and "System32" in o.value for o in found
    )


def test_strings_respects_min_len_and_empty(tmp_path: Path) -> None:
    p = _write(tmp_path, "short", b"ab\x00cd\x00efghijkl")
    found = [o.value for o in strings.analyze(p, min_len=5) if o.kind == "string"]
    assert found == ["efghijkl"]
    empty = strings.analyze(_write(tmp_path, "e", b""))
    assert [o for o in empty if o.kind == "string"] == []


# --- magic ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("head", "media"),
    [
        (b"\x7fELF\x02\x01\x01", "application/x-elf"),
        (b"\x89PNG\r\n\x1a\n\x00", "image/png"),
        (b"%PDF-1.7\n", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b\x08\x00", "application/gzip"),
    ],
)
def test_magic_recognises_signatures(tmp_path: Path, head: bytes, media: str) -> None:
    p = _write(tmp_path, "m", head + b"\x00" * 16)
    [obs] = magic.analyze(p)
    assert obs.attributes["media_type"] == media


def test_magic_distinguishes_text_from_binary(tmp_path: Path) -> None:
    text = magic.analyze(_write(tmp_path, "t", b"hello, world\n"))
    assert text[0].attributes["media_type"] == "text/plain"
    binary = magic.analyze(_write(tmp_path, "x", b"\x01\x02\x00\x03\xff"))
    assert binary[0].attributes["media_type"] == "application/octet-stream"


# --- entropy ----------------------------------------------------------------


def test_entropy_low_for_zeros_high_for_random(tmp_path: Path) -> None:
    zeros = entropy.analyze(_write(tmp_path, "z", b"\x00" * 8192))
    overall_zero = next(o for o in zeros if o.attributes["scope"] == "overall")
    assert float(overall_zero.value) < 0.1
    assert overall_zero.attributes["high"] == "False"

    rnd = entropy.analyze(_write(tmp_path, "r", os.urandom(8192)))
    overall_rnd = next(o for o in rnd if o.attributes["scope"] == "overall")
    assert float(overall_rnd.value) > 7.5
    assert overall_rnd.attributes["high"] == "True"
    # a high-entropy block is flagged with an offset
    assert any(o.attributes["scope"] == "block" for o in rnd)


# --- encoding ---------------------------------------------------------------


def test_encoding_decodes_base64(tmp_path: Path) -> None:
    p = _write(tmp_path, "b64", base64.b64encode(b"super secret payload"))
    decoded = [o for o in encoding.analyze(p) if o.kind == "decoded"]
    assert any(
        o.attributes["encoding"] == "base64" and "super secret payload" in o.value
        for o in decoded
    )


def test_encoding_detects_gzip(tmp_path: Path) -> None:
    p = _write(tmp_path, "g", gzip.compress(b"hello"))
    assert any("gzip" in o.value for o in encoding.analyze(p))


def test_encoding_decodes_hex_and_url(tmp_path: Path) -> None:
    hexed = _write(tmp_path, "h", b"48656c6c6f21")  # "Hello!"
    assert any(
        o.attributes.get("encoding") == "hex" and "Hello!" in o.value
        for o in encoding.analyze(hexed)
    )
    urly = _write(tmp_path, "u", b"a%20b%2Fc")
    assert any(
        o.attributes.get("encoding") == "url" and "a b/c" in o.value
        for o in encoding.analyze(urly)
    )


# --- hexview ----------------------------------------------------------------


def test_hexview_formats_offset_hex_ascii(tmp_path: Path) -> None:
    p = _write(tmp_path, "hv", b"AB\x00\xff")
    [obs] = hexview.analyze(p)
    assert obs.value.startswith("00000000  41 42 00 ff")
    assert "|AB..|" in obs.value


# --- logparse ---------------------------------------------------------------


def test_logparse_syslog_clf_iso_and_unmatched(tmp_path: Path) -> None:
    log = (
        "Jan  2 03:04:05 host sshd[1]: Failed password for root\n"
        '127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 2326\n'
        "2026-10-04T12:00:00Z service started\n"
        "a line with no timestamp\n"
    )
    p = _write(tmp_path, "log", log.encode("utf-8"))
    rows = logparse.analyze(p)
    by_msg = {o.value: o.attributes for o in rows}
    assert by_msg["sshd[1]: Failed password for root"]["source"] == "host"
    assert "GET / HTTP/1.1" in " ".join(by_msg)
    assert by_msg["service started"]["timestamp"].startswith("2026-10-04")
    assert by_msg["a line with no timestamp"]["timestamp"] == ""


# --- keyed_decrypt ----------------------------------------------------------


def test_keyed_decrypt_fernet_round_trip(tmp_path: Path) -> None:
    fernet = pytest.importorskip("cryptography.fernet")
    key = fernet.Fernet.generate_key()
    token = fernet.Fernet(key).encrypt(b"recovered cleartext")
    p = _write(tmp_path, "enc", token)
    [obs] = keyed_decrypt.analyze(p, key=key.decode(), algorithm="fernet")
    assert obs.kind == "decrypted"
    assert obs.value == "recovered cleartext"


def test_keyed_decrypt_wrong_key_is_a_note_not_a_crash(tmp_path: Path) -> None:
    fernet = pytest.importorskip("cryptography.fernet")
    token = fernet.Fernet(fernet.Fernet.generate_key()).encrypt(b"x")
    p = _write(tmp_path, "enc", token)
    [obs] = keyed_decrypt.analyze(
        p, key=fernet.Fernet.generate_key().decode(), algorithm="fernet"
    )
    assert obs.kind == "note"
    assert "failed" in obs.value


# --- keyed_decrypt AES paths ------------------------------------------------


def test_keyed_decrypt_aes_gcm_round_trip(tmp_path: Path) -> None:
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = aead.AESGCM(key).encrypt(nonce, b"gcm cleartext", None)
    p = _write(tmp_path, "g", ct)
    [obs] = keyed_decrypt.analyze(
        p, key=key.hex(), algorithm="aes-gcm", nonce=nonce.hex()
    )
    assert obs.kind == "decrypted"
    assert obs.value == "gcm cleartext"


def test_keyed_decrypt_aes_gcm_without_nonce_is_a_note(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    p = _write(tmp_path, "g", b"whatever")
    [obs] = keyed_decrypt.analyze(p, key="00" * 32, algorithm="aes-gcm")
    assert obs.kind == "note"
    assert "nonce" in obs.value


def test_keyed_decrypt_unknown_algorithm_is_a_note(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    p = _write(tmp_path, "g", b"x")
    [obs] = keyed_decrypt.analyze(p, key="k", algorithm="rot-47")
    assert obs.kind == "note"
    assert "unknown algorithm" in obs.value


def test_keyed_decrypt_aes_cbc_round_trip(tmp_path: Path) -> None:
    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")

    key = os.urandom(32)
    iv = os.urandom(16)
    plaintext = b"cbc cleartext!!!"  # exactly one 16-byte block, no padding needed
    enc = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CBC(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    p = _write(tmp_path, "c", ct)
    [obs] = keyed_decrypt.analyze(p, key=key.hex(), algorithm="aes-cbc", nonce=iv.hex())
    assert obs.kind == "decrypted"
    assert obs.value == "cbc cleartext!!!"


def test_keyed_decrypt_aes_cbc_without_iv_is_a_note(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    p = _write(tmp_path, "c", b"x" * 16)
    [obs] = keyed_decrypt.analyze(p, key="00" * 32, algorithm="aes-cbc")
    assert obs.kind == "note"
    assert "iv" in obs.value


def test_keyed_decrypt_decodes_a_base64_key(tmp_path: Path) -> None:
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = aead.AESGCM(key).encrypt(nonce, b"via base64 key", None)
    p = _write(tmp_path, "g", ct)
    # a base64 key carries '+/=' / upper+lower letters, so it is NOT mistaken for hex
    [obs] = keyed_decrypt.analyze(
        p,
        key=base64.b64encode(key).decode(),
        algorithm="aes-gcm",
        nonce=base64.b64encode(nonce).decode(),
    )
    assert obs.kind == "decrypted"
    assert obs.value == "via base64 key"
