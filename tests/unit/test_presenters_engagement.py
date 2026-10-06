"""L1: the shared `show engagement` presenter -- one code path, both surfaces."""

from __future__ import annotations

from skuggi.common import palette
from skuggi.engagement.scope import EngagementConfig
from skuggi.frontend.presenters_engagement import present_engagement


def test_present_engagement_none_points_at_setup() -> None:
    [line] = present_engagement(None, "repl")
    assert "no engagement loaded" in line.text
    assert "set engagement setup" in line.text


def test_present_engagement_paints_methods_for_both_surfaces() -> None:
    cfg = EngagementConfig(
        name="acme", timezone="UTC", allowed_methods=frozenset({"recon", "scan"})
    )
    for surface in ("repl", "shell"):
        lines = present_engagement(cfg, surface)
        assert any("engagement: acme" in line.text for line in lines)
        # the methods line carries palette-painted spans, same on each surface
        method_line = next(line for line in lines if "methods:" in line.text)
        styles = {seg[1] for seg in (method_line.spans or [])}
        assert palette.method_style("recon") in styles
        assert palette.method_style("scan") in styles
