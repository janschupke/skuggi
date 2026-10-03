"""L1: the pure per-file-type semantic config differ.

reconcile detects *that* a file drifted; this is the pure core that says *what*
drifted -- whole entries for the keyed lists (tools / commands), dotted-path
properties for the objects (config / layout). Direction is installed -> packaged
(what an overwrite would do), so these pin that added/removed/changed mean exactly
that, per file type, without touching disk.
"""

from __future__ import annotations

from skuggi.install import configdiff


def test_keyed_list_added_removed_and_changed_commands() -> None:
    installed = {
        "commands": [
            {"name": "keep", "argv": ["nmap", "-sV"], "description": "x"},
            {"name": "gone", "argv": ["curl", "-s"], "description": "y"},
            {"name": "edit", "argv": ["gobuster", "dir"], "description": "z"},
        ]
    }
    packaged = {
        "commands": [
            {"name": "keep", "argv": ["nmap", "-sV"], "description": "x"},
            {"name": "edit", "argv": ["gobuster", "dir", "-u"], "description": "z"},
            {"name": "fresh", "argv": ["ffuf", "-u"], "description": "w"},
        ]
    }
    d = configdiff.diff("commands.json", installed, packaged)
    # Only in the template -> an overwrite adds it; only installed -> removed.
    assert any("fresh" in e for e in d.added)
    assert any("gone" in e for e in d.removed)
    # The command with the same name but a changed argv is a per-field change.
    change = next(c for c in d.changed if c.path == "edit.argv")
    assert "gobuster" in change.old
    assert "-u" in change.new
    assert not d.empty


def test_keyed_list_tools_render_name_and_binary() -> None:
    installed: dict[str, object] = {"tools": []}
    packaged = {"tools": [{"name": "nmap", "binary": "nmap", "method": "scan"}]}
    d = configdiff.diff("tools.json", installed, packaged)
    assert d.added == ("nmap [nmap]",)
    assert d.removed == ()
    assert d.changed == ()


def test_object_property_old_to_new_for_config() -> None:
    installed = {"provider": "openai", "retrieve_k": 4, "dropped": 1}
    packaged = {"provider": "anthropic", "retrieve_k": 4, "added_key": "v"}
    d = configdiff.diff("config.json", installed, packaged)
    change = next(c for c in d.changed if c.path == "provider")
    assert change.old == '"openai"'
    assert change.new == '"anthropic"'
    assert any("added_key" in e for e in d.added)
    assert any("dropped" in e for e in d.removed)


def test_object_recurses_nested_dicts_to_dotted_paths() -> None:
    installed = {"timeouts": {"command": 60}}
    packaged = {"timeouts": {"command": 120}}
    d = configdiff.diff("layout.json", installed, packaged)
    change = next(c for c in d.changed if c.path == "timeouts.command")
    assert change.old == "60"
    assert change.new == "120"


def test_object_compares_lists_by_value() -> None:
    installed = {"recon_subdirs": ["nmap", "web"]}
    packaged = {"recon_subdirs": ["nmap", "dirs", "web"]}
    d = configdiff.diff("layout.json", installed, packaged)
    change = next(c for c in d.changed if c.path == "recon_subdirs")
    assert "dirs" in change.new


def test_missing_install_is_all_added() -> None:
    packaged = {"commands": [{"name": "a", "argv": ["x"], "description": "d"}]}
    d = configdiff.diff("commands.json", {}, packaged)
    assert len(d.added) == 1
    assert d.removed == ()
    assert d.changed == ()
    assert not d.empty


def test_identical_is_empty() -> None:
    same = {"tools": [{"name": "nmap", "binary": "nmap"}]}
    assert configdiff.diff("tools.json", same, dict(same)).empty
    obj = {"provider": "openai", "nested": {"k": 1}}
    assert configdiff.diff("config.json", obj, dict(obj)).empty
