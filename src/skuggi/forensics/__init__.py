"""The forensics subsystem: a strictly read-only, engagement-free analysis loop.

Forensics is its own operating mode (see ``skuggi.common.modes``) bound to a
*case* (``skuggi.engagement.case``) rather than an engagement. It examines local
evidence read-only -- never modifying an evidence file, never executing an
artifact under analysis -- and records detailed evidence + a chain-of-custody
procedure log into the case's own ledger, then emits a cited Markdown/PDF report.

Built on the shared ``skuggi.intel`` core like the OSINT and research loops, but
its collectors are local analyzers (``forensics.analyzers``) and a small set of
gated read-only external utilities, never network sources.
"""
