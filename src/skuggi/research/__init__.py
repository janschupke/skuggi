"""The agentic public-source research loop.

A third LangGraph, a sibling of the OSINT loop and built on the same shared core
(:mod:`skuggi.intel`): a planner emits a todo DAG of research tasks, a dependency-
aware scheduler walks it, collectors query PUBLIC sources only (web search, GitHub,
version feeds, CVE/Exploit-DB, and -- when installed -- local searchsploit /
metasploit module metadata), and a verifier assembles a structured profile and
re-plans the gaps.

Unlike OSINT, research is **engagement-independent**: its subject is an abstract
service / tech stack / app / company ("wordpress 6.x", "jenkins"), it runs without
an engagement (writing to ``./research`` with a warning when none is loaded), and
it produces a structured report -- NOT ledger findings. It never performs offensive
scanning: every research source is a passive, public-data ``recon``-tier query, and
there is no code path to an active source.
"""
