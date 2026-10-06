"""L1: the routing pieces the REPL and the daemon share."""

from __future__ import annotations

import ast
from pathlib import Path

from skuggi.common.modes import MODES
from skuggi.frontend import verb_router, verbs


def test_verb_router_does_not_import_a_front_end() -> None:
    """The shared router must not import `tui`/`daemon`.

    Both front-ends import this module; if it imported either of them back, the
    extraction would close an import loop. Pin the leaf invariant the module
    comment relies on (it may use only `verbs` + `common`).
    """
    tree = ast.parse(Path(verb_router.__file__).read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "skuggi"
        ):
            modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            modules.extend(a.name for a in node.names if a.name.startswith("skuggi"))
    offenders = [
        m for m in modules if m in ("skuggi.frontend.tui", "skuggi.frontend.daemon")
    ]
    assert offenders == [], f"verb_router must not import a front end: {offenders}"


def test_should_audit_matches_the_predicate_for_every_known_verb() -> None:
    """One source for the audit gate: known, available, non-engagement."""
    for mode in MODES:
        for verb in verbs.KNOWN:
            expected = verbs.is_available(verb, mode) and not verbs.is_engagement(verb)
            assert verb_router.should_audit(verb, mode) is expected


def test_should_audit_concrete_cases() -> None:
    assert verb_router.should_audit("show", "pentest") is True  # control verb
    assert verb_router.should_audit("add", "pentest") is False  # engagement verb
    assert verb_router.should_audit("bogus", "pentest") is False  # unknown verb


def test_noun_usage_lists_the_grouping_verb_nouns_per_surface() -> None:
    repl = verb_router.noun_usage("show", "repl")
    shell = verb_router.noun_usage("show", "shell")
    assert "config" in repl
    assert "|" in repl
    # The hint is formatted for its surface, so the two differ by the prefix.
    assert repl != shell
    assert repl == verbs.cmd(
        f"show <{' | '.join(n.name for n in verbs.nouns_of('show'))}>", "repl"
    )


def test_resolve_noun_hit_miss_and_remainder() -> None:
    router = {"alpha": "A", "beta": "B"}
    assert verb_router.resolve_noun(router, "alpha the rest") == ("A", "the rest")
    assert verb_router.resolve_noun(router, "ALPHA x") == ("A", "x")  # case-folded
    assert verb_router.resolve_noun(router, "alpha") == ("A", "")  # no remainder
    assert verb_router.resolve_noun(router, "gamma leftover") == (None, "leftover")


def test_build_router_wraps_actions_and_merges_extras() -> None:
    actions = {"x": "ACT"}
    router = verb_router.build_router(actions, lambda a: f"wrapped:{a}")
    assert router == {"x": "wrapped:ACT"}

    with_extras = verb_router.build_router(
        actions, lambda a: f"wrapped:{a}", {"y": "extra"}
    )
    assert with_extras == {"x": "wrapped:ACT", "y": "extra"}

    # An extra on the same key wins over the wrapped action.
    override = verb_router.build_router(actions, lambda a: f"wrapped:{a}", {"x": "own"})
    assert override == {"x": "own"}
