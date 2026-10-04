"""Shared machinery for the agentic intelligence loops (OSINT and research).

Both ``skuggi.osint`` and ``skuggi.research`` are the same shape -- a planner
emits a dependency DAG of tasks, a scheduler walks it, collectors run each task
and write a structured artifact, and a verifier checks coverage and re-plans the
gaps. The subsystem-agnostic half of that lives here so neither package
duplicates it and ``research`` never has to import ``osint``:

- :mod:`skuggi.intel.schema` -- the generic datum/result corpus (``IntelItem`` /
  ``IntelResult``) and the ``CollectTask`` a collector reads.
- :mod:`skuggi.intel.http` -- the injectable HTTP/collect-context seam (the one
  place real network I/O happens).
- :mod:`skuggi.intel.scheduler` -- the pure dependency-DAG logic.
- :mod:`skuggi.intel.store` -- the confined, redacted JSON artifact writer.
- :mod:`skuggi.intel.collectors` -- the ``Collector`` protocol plus the two
  source handlers both subsystems share (web search and GitHub).

What stays per-subsystem: the task/plan/verdict schema, the scope/guard, the
prompts, the deps, the state, the graph wiring, the runner, and core wiring.
"""
