"""L3: `reconcile <file>` reloads config, so `cmd` reflects it without restart.

The bug this guards: an install seeded from an older template has a ``tools.json``
missing a tool's output convention, so ``cmd nmap-full`` renders without the
``-oA recon/nmap/...`` path. Overwriting from the packaged template must not only
rewrite the file but reload the in-memory registry, so the very next ``cmd``
resolve shows the restored output path.
"""

from __future__ import annotations

import json
from pathlib import Path

from skuggi.agent.core import AgentCore
from skuggi.common import home
from skuggi.install.init import initialise
from tests.conftest import offline_settings


def _strip_nmap_output(config_dir: Path) -> None:
    """Rewrite tools.json as an old install would have it: nmap, no output conv."""
    tools_path = config_dir / "tools.json"
    data = json.loads(tools_path.read_text(encoding="utf-8"))
    for tool in data["tools"]:
        if tool["name"] == "nmap":
            for key in ("output_flag", "output_dir", "output_kind", "output_ext"):
                tool.pop(key, None)
    tools_path.write_text(json.dumps(data), encoding="utf-8")


def test_overwrite_reloads_so_the_next_cmd_shows_the_output_path(
    tmp_path: Path,
) -> None:
    # Seed the (isolated) config home from the packaged templates, then age the
    # tool registry so nmap lacks its output convention.
    initialise(migrate_from=None)
    config_dir = home.config_home()
    _strip_nmap_output(config_dir)

    core = AgentCore(offline_settings(tmp_path))

    before = core.cmds.plan("nmap-full").raw
    assert "-oA" not in before  # stale registry: no output path rendered

    backup = core.reconcile_overwrite("tools.json")
    assert backup is not None
    assert backup.is_file()

    after = core.cmds.plan("nmap-full").raw
    assert "-oA recon/nmap/$(date +%Y-%m-%d_%H%M%S)_${target}" in after
    assert core.stale_configs() == ()  # no longer behind the template
