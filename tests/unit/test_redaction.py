"""The deterministic redaction boundary: detectors, vault, and the tripwire.

These are the proof the whole data-plane design rests on, so they are explicit
about three properties: every secret category is detected and masked; a value
masked with a vault round-trips back to the original via rehydrate; and nothing
sensitive survives a redact pass (the tripwire finds a leak when one is planted).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skuggi.security.policy import RedactionPolicy
from skuggi.security.redaction import REDACTED, redact, scan
from skuggi.security.tripwire import RedactionLeakError, assert_clean, scrub
from skuggi.security.vault import open_vault

# A deliberately fake key fixture. The BEGIN header is assembled from pieces so
# the pre-commit detect-private-key hook (which scans source bytes for a
# contiguous "BEGIN ... PRIVATE KEY") does not block commits; the runtime string
# is a well-formed PEM block the detector under test must still catch.
_PEM_BEGIN = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
PEM = (
    f"{_PEM_BEGIN}\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
    "-----END OPENSSH PRIVATE KEY-----"
)

# (label, text containing exactly one secret, the KIND it should be masked as)
SECRET_CASES = [
    ("pem_key", f"here is a key:\n{PEM}\n", "KEY"),
    (
        "jwt",
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123DEFghiJKL",
        "JWT",
    ),
    ("aws_key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE here", "AWSKEY"),
    ("gh_token", "use ghp_1234567890abcdefABCDEF1234567890abcd now", "TOKEN"),
    ("openai_key", "export KEY=sk-abcdefghijklmnopqrstuvwxyz0123 done", "TOKEN"),
    ("auth_header", "Authorization: Bearer deadbeefcafe12345678\n", "AUTH"),
    ("bearer", "sent token hunter2hunter2hunter2 in header", "TOKEN"),
    ("url_cred", "ftp://admin:s3cr3tpass@10.0.0.5/pub listing", "URLCRED"),
    ("password_kv", "password: SuperSecret123! wrote it", "PASSWORD"),
    ("bcrypt", "hash $2b$12$abcdefghijklmnopqrstuv stored", "HASH"),
    ("email", "contact alice.smith@victim-corp.example for access", "EMAIL"),
    ("credit_card", "card 4111 1111 1111 1111 on file", "CARD"),
]


@pytest.fixture
def policy() -> RedactionPolicy:
    return RedactionPolicy()


@pytest.mark.parametrize(
    ("label", "text", "kind"),
    SECRET_CASES,
    ids=[case[0] for case in SECRET_CASES],
)
def test_each_secret_category_is_detected(
    label: str, text: str, kind: str, policy: RedactionPolicy
) -> None:
    hits = scan(text, policy)
    assert hits, f"{label}: nothing detected"
    assert any(h.kind == kind for h in hits), f"{label}: expected a {kind} hit"


@pytest.mark.parametrize(
    ("label", "text", "kind"),
    SECRET_CASES,
    ids=[case[0] for case in SECRET_CASES],
)
def test_redact_one_way_masks_and_assert_clean_passes(
    label: str, text: str, kind: str, policy: RedactionPolicy
) -> None:
    masked = redact(text, policy)
    assert REDACTED in masked, f"{label}: not masked"
    # The tripwire must agree the masked text is clean.
    assert_clean(masked, policy)


def test_assert_clean_raises_when_a_secret_is_planted(
    policy: RedactionPolicy,
) -> None:
    with pytest.raises(RedactionLeakError):
        assert_clean("leaked ghp_1234567890abcdefABCDEF1234567890abcd here", policy)


def test_scrub_masks_residual_and_is_noop_when_clean(policy: RedactionPolicy) -> None:
    dirty = "token ghp_1234567890abcdefABCDEF1234567890abcd end"
    cleaned = scrub(dirty, policy)
    assert REDACTED in cleaned
    assert scrub("nothing sensitive here", policy) == "nothing sensitive here"


def test_allow_set_exempts_scope_values() -> None:
    # An in-scope host that would match the email/hostname shape must survive.
    policy = RedactionPolicy.from_scope(allow=["scanme.example.com"])
    text = "scanning scanme.example.com now"
    assert redact(text, policy) == text


def test_from_scope_drops_blank_allow_entries() -> None:
    policy = RedactionPolicy.from_scope(allow=["", "   ", "10.0.0.1"])
    assert policy.allow == frozenset({"10.0.0.1"})


def test_empty_text_is_untouched(policy: RedactionPolicy) -> None:
    assert redact("", policy) == ""
    assert scan("", policy) == []


def test_min_len_gates_short_password_values() -> None:
    policy = RedactionPolicy(min_secret_len=8)
    assert redact("password: abc", policy) == "password: abc"  # too short
    assert REDACTED in redact("password: abcdefghij", policy)


def test_category_toggle_disables_a_detector() -> None:
    policy = RedactionPolicy(emails=False)
    text = "mail bob@victim.example please"
    assert redact(text, policy) == text


def test_overlapping_matches_are_masked_once() -> None:
    # The bearer token inside an auth header must not double-wrap.
    text = "Authorization: Bearer abcdef1234567890abcdef"
    masked = redact(text, RedactionPolicy())
    assert masked.count(REDACTED) == 1


def test_vault_roundtrip_is_identity(tmp_path: Path) -> None:
    with open_vault(tmp_path / ".vault.db") as vault:
        text = (
            "creds at ftp://admin:SuperSecret123@10.0.0.5/ and "
            "key sk-abcdefghijklmnopqrstuvwxyz0123 done"
        )
        masked = redact(text, RedactionPolicy(), vault)
        assert "SuperSecret123" not in masked
        assert "sk-abcdefghijklmnopqrstuvwxyz0123" not in masked
        assert "«" in masked
        # Rehydration restores exactly the original.
        assert vault.rehydrate(masked) == text


def test_vault_placeholder_is_stable_for_a_value(tmp_path: Path) -> None:
    with open_vault(tmp_path / ".vault.db") as vault:
        first = vault.intern("hunter2hunter2", "PASSWORD")
        second = vault.intern("hunter2hunter2", "PASSWORD")
        assert first == second
        assert vault.resolve(first) == "hunter2hunter2"


def test_vault_distinct_values_get_distinct_placeholders(tmp_path: Path) -> None:
    with open_vault(tmp_path / ".vault.db") as vault:
        assert vault.intern("valueoneeee", "TOKEN") != vault.intern(
            "valuetwoooo", "TOKEN"
        )


def test_vault_salt_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / ".vault.db"
    with open_vault(path) as vault:
        token = vault.intern("persistent-secret", "TOKEN")
    with open_vault(path) as reopened:
        assert reopened.intern("persistent-secret", "TOKEN") == token


def test_vault_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / ".vault.db"
    with open_vault(path):
        pass
    assert (path.stat().st_mode & 0o777) == 0o600


def test_rehydrate_leaves_unknown_placeholders_intact(tmp_path: Path) -> None:
    with open_vault(tmp_path / ".vault.db") as vault:
        assert (
            vault.rehydrate("see «TOKEN:zzzzzz» please") == "see «TOKEN:zzzzzz» please"
        )


def test_resolve_unknown_placeholder_is_none(tmp_path: Path) -> None:
    with open_vault(tmp_path / ".vault.db") as vault:
        assert vault.resolve("«TOKEN:nope12»") is None
