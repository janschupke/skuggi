"""Magic-byte file-type identification (a small, in-process signature table).

A deterministic first-pass type ID so a finding can say what an artifact *is*
without shelling out to ``file``. Not exhaustive -- the gated ``file`` tool covers
the long tail -- but it recognises the formats that matter in triage (executables,
archives, images, documents, captures) from their leading bytes.
"""

from __future__ import annotations

from pathlib import Path

from skuggi.forensics.analyzers.base import Observation

# (magic prefix, media type, human label). Ordered longest/most-specific first so
# a prefix match is unambiguous.
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x7fELF", "application/x-elf", "ELF executable"),
    (b"MZ", "application/x-dosexec", "PE/DOS executable"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
    (b"GIF87a", "image/gif", "GIF image"),
    (b"GIF89a", "image/gif", "GIF image"),
    (b"%PDF-", "application/pdf", "PDF document"),
    (b"PK\x03\x04", "application/zip", "ZIP archive (or OOXML/JAR)"),
    (b"\x1f\x8b", "application/gzip", "gzip stream"),
    (b"BZh", "application/x-bzip2", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "application/x-xz", "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip archive"),
    (b"Rar!\x1a\x07", "application/x-rar", "RAR archive"),
    (b"\xd4\xc3\xb2\xa1", "application/vnd.tcpdump.pcap", "pcap capture"),
    (b"\x0a\x0d\x0d\x0a", "application/x-pcapng", "pcapng capture"),
    (b"SQLite format 3\x00", "application/x-sqlite3", "SQLite database"),
)


def analyze(path: Path) -> list[Observation]:
    """Identify `path` from its leading bytes; else report binary vs text."""
    with path.open("rb") as fh:
        head = fh.read(32)
    for prefix, media_type, label in _SIGNATURES:
        if head.startswith(prefix):
            return [
                Observation(
                    kind="magic",
                    value=label,
                    attributes={"media_type": media_type, "magic": prefix.hex()},
                )
            ]
    # No signature: distinguish plausibly-text from opaque binary (a cheap, useful
    # triage signal), based on whether the head decodes as UTF-8 with no NULs.
    is_text = b"\x00" not in head
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        is_text = False
    label = "text data" if is_text else "unrecognised binary"
    media = "text/plain" if is_text else "application/octet-stream"
    return [Observation(kind="magic", value=label, attributes={"media_type": media})]
