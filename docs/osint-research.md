# OSINT and research: the autonomous intelligence loops

Beyond the main planner→worker→critic turn graph, skuggi has two autonomous
intelligence loops that collect from external sources, plus a shared core they are
both built on.

Both are **agentic loops** (plan → collect ⇄ schedule → verify → re-plan | respond),
compiled as their own LangGraph graphs, and both import *down* into
`agent`/`engagement`/`security` — never the reverse. Collected text passes through
the same data-plane redaction and workspace-confinement as everything else (see
[architecture.md](architecture.md#the-data-plane-boundary)).

## `osint` — engagement-scoped reconnaissance

```
/skuggi osint enumerate acme's external attack surface
```

The `osint` verb (offensive modes only) runs the autonomous OSINT reconnaissance
loop over **subjects** — organizations, apex domains, people/usernames, GitHub orgs —
not IPs. It is a distinct scope dimension from the network/host command boundary:

- It runs only when the engagement scope has an `osint` block
  ([OsintScope](../src/skuggi/engagement/scope.py)); absent, the loop refuses.
- The OSINT guard ([engagement/osint_guard.py](../src/skuggi/engagement/osint_guard.py))
  denies, deny-by-default, any task whose subject is outside the scope or whose
  source is not in `enabled_sources`.
- `passive_only` (default `true`) holds back active, subject-touching sources
  (browser scraping); `autonomous_ceiling` (default `recon`) is the OSINT analogue
  of the engagement's autonomous ceiling — passive HTTP recon auto-runs, browser /
  scraper sources escalate.

Sources (`enabled_sources`): `crtsh`, `dns`, `github`, `websearch` (passive,
`recon` tier); `linkedin`, `ats`, `social`, `shodan` (active, need the browser /
an API key). Output is written to the engagement's `osint/` directory.

## `research` — engagement-independent public-source research

```
/skuggi research CVEs and known exploits for Apache 2.4.49
```

The `research` verb researches a service / technology / application / company from
public sources. Unlike OSINT it is **engagement-independent** and **report-only** (it
writes no ledger findings): it produces a structured briefing into the engagement's
`research/` directory, or `./research` when no engagement is loaded. Its public-
sources-only scope is built in. Collectors: CVE (the keyless NVD API by default;
`NVD_API_KEY` raises the rate limit), Exploit-DB, end-of-life/version data, plus
optional local `searchsploit`/`metasploit`.

## `intel` — the shared core

Both loops are built on [src/skuggi/intel/](../src/skuggi/intel/): the `IntelItem`/
`IntelResult`/`CollectTask` schema, the injectable fetch/collect-context HTTP seam, a
pure dependency-DAG scheduler, the confined + redacted JSON store, and the
`Collector` protocol with the source handlers both loops share (web search, GitHub).
A deterministic input guard on the local-tool collectors keeps a hostile result from
steering a subprocess. Pure-I/O collectors run concurrently per superstep
(`intel_concurrency`); driver-backed collectors run serially, so a parallel superstep
never spawns a browser pool.

## Configuration

Credentials are **env-only** (never `config.json`) — a collector is usable only when
its source is authorized in scope *and* its credential is present:

| Key | Purpose |
|---|---|
| `SHODAN_API_KEY` | the `shodan` OSINT source |
| `APIFY_TOKEN` | Apify-backed scraper sources (linkedin/ats/social) |
| `OSINT_SEARCH_API_KEY` | a keyed websearch backend (optional) |
| `NVD_API_KEY` | a higher NVD rate limit for the research CVE collector |

Non-secret tuning (overridable via `config.json` or `SKUGGI_*`):

| Key | Default | Purpose |
|---|---|---|
| `osint_source_config` | `{"websearch": {"backend": "duckduckgo"}}` | per-source tuning (search backend/endpoint, GitHub api base, apify actor id) |
| `research_source_config` | `{"websearch": {"backend": "duckduckgo"}}` | same, for the research loop |
| `osint_max_tasks` / `osint_max_replans` | 12 / 2 | bound the OSINT loop |
| `research_max_tasks` / `research_max_replans` | 10 / 2 | bound the research loop |
| `intel_concurrency` | 4 | max pure-I/O collectors per superstep |

The default websearch backend is the no-key DuckDuckGo HTML endpoint, so both loops
work with no credentials at all (fewer sources).
