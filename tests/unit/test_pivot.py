"""L1: foothold persistence + runtime reachability routing (pivot, P0)."""

from __future__ import annotations

from pathlib import Path

from skuggi.engagement.pivot import route_for
from skuggi.persistence.ledger import open_ledger
from skuggi.persistence.ledger_schema import FootholdRow


def _foothold(**kw: object) -> FootholdRow:
    base: dict[str, object] = {
        "id": 1,
        "session_id": "s1",
        "host": "portal.bastion.lab",
        "transport": "command",
        "template": "python3 -c '{cmd}'",
        "secret_ref": "",
        "reachable_networks": "10.9.0.0/24",
        "reachable_hosts": "admin.internal",
        "created_at": "2026-10-05T00:00:00+00:00",
    }
    base.update(kw)
    return FootholdRow(**base)  # type: ignore[arg-type]


def test_route_via_foothold_for_an_internal_host() -> None:
    fh = _foothold()
    assert route_for("admin.internal", [fh]).foothold is fh  # exact host match
    assert route_for("10.9.0.10", [fh]).foothold is fh  # inside a reachable CIDR


def test_route_is_direct_for_a_reachable_or_unknown_target() -> None:
    fh = _foothold()
    assert route_for("10.9.9.9", [fh]).foothold is None  # outside the reachable net
    assert route_for("example.com", [fh]).foothold is None  # unlisted host
    assert route_for("", [fh]).foothold is None  # no target
    assert route_for("admin.internal", []).foothold is None  # no footholds


def test_first_reaching_foothold_wins() -> None:
    a = _foothold(id=1, host="dmz-a", reachable_networks="10.9.0.0/24")
    b = _foothold(id=2, host="dmz-b", reachable_networks="10.9.0.0/24")
    assert route_for("10.9.0.5", [a, b]).foothold is a


def test_ledger_records_a_foothold_without_storing_the_secret(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with open_ledger(path) as ledger:
        ledger.start_session("s1", engagement_name="e", mode="pentest")
        fid = ledger.record_foothold(
            session_id="s1",
            host="portal.bastion.lab",
            template="ssh root@portal -- {cmd}",
            secret_ref="«CRED:ab12cd»",
            reachable_networks="10.9.0.0/24",
            reachable_hosts="admin.internal",
        )
        assert fid > 0
        [fh] = ledger.footholds_for("s1")
        assert fh.host == "portal.bastion.lab"
        assert fh.reachable_hosts == "admin.internal"
        assert fh.secret_ref == "«CRED:ab12cd»"
    # Only the vault placeholder is stored (a real secret never reaches this table;
    # the journal interns it first -- covered end-to-end in the pivot verb tests).
    assert "«CRED:ab12cd»".encode() in path.read_bytes()


def test_ledger_clears_footholds(tmp_path: Path) -> None:
    with open_ledger(tmp_path / "ledger.db") as ledger:
        ledger.start_session("s1", engagement_name="e", mode="pentest")
        ledger.record_foothold(session_id="s1", host="a")
        ledger.record_foothold(session_id="s1", host="b")
        assert len(ledger.footholds_for("s1")) == 2
        assert ledger.clear_footholds("s1") == 2
        assert ledger.footholds_for("s1") == []
