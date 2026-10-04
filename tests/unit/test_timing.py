"""The per-turn latency collector: a context-scoped, no-op-outside accumulator."""

from __future__ import annotations

from skuggi.common.timing import collect_turn_timing, record_call


def test_record_call_is_a_noop_outside_a_turn() -> None:
    # No collector active: recording must not raise and must keep no state, so the
    # eval harness / tests that invoke the model off the turn path pay nothing.
    record_call("planner", 1.0, repaired=False)  # must not raise


def test_collector_sums_time_per_node_and_counts_calls() -> None:
    with collect_turn_timing() as timing:
        record_call("planner", 2.0, repaired=False)
        record_call("worker", 5.0, repaired=False)
        record_call("worker", 1.0, repaired=True)  # a repair retry on the worker
        record_call("critic", 3.0, repaired=False)

    assert timing.by_node() == {"planner": 2.0, "worker": 6.0, "critic": 3.0}
    assert timing.llm_s == 11.0
    assert timing.call_count == 4
    assert timing.repair_count == 1


def test_collector_is_scoped_and_reset_on_exit() -> None:
    with collect_turn_timing() as first:
        record_call("planner", 1.0, repaired=False)
    # The first collector is closed; a call now lands nowhere (no leak forward).
    record_call("worker", 9.0, repaired=False)
    assert first.call_count == 1

    with collect_turn_timing() as second:
        record_call("critic", 2.0, repaired=False)
    assert second.by_node() == {"critic": 2.0}


def test_empty_turn_has_zero_totals() -> None:
    with collect_turn_timing() as timing:
        pass
    assert timing.llm_s == 0.0
    assert timing.call_count == 0
    assert timing.by_node() == {}
