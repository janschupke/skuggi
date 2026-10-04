"""The agentic OSINT reconnaissance loop.

A second LangGraph, parallel to the conversational turn graph: a planner emits a
todo DAG of OSINT tasks, a dependency-aware scheduler walks it, collectors run each
task scope-checked against the OSINT boundary (``engagement.osint_guard``) and
write structured artifacts, and a verifier checks coverage and re-plans the gaps.
It reuses the shared request seam (``agent.requests``), the redaction egress, the
ledger/report pipeline, and the engagement workspace -- sharing logic, not deps.
"""
