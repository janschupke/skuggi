# Usage: the verb grammar, the command cheatsheet, and memory

skuggi is driven by a small **verb-object grammar**, shared verbatim by all three
front-ends:

- the wrapped shell — `/skuggi <verb> …` (a bare word is your real shell);
- the `/skuggi` chat loop — a bare `<verb> …`;
- the standalone REPL (`skuggi-repl`) — `/<verb> …`, with bare text an implicit
  `ask`.

The first word is the **verb**; the rest is its input. Four **grouping verbs**
(`show` / `set` / `add` / `remove`) take a *noun* as their first word
(`show findings`, `set mode redteam`, `add note …`, `remove memory 3`) and route
on it. There is one source of truth for the whole set —
[src/skuggi/frontend/verbs.py](../src/skuggi/frontend/verbs.py) — so the three
surfaces can never drift, and `help` (or `help <verb>`) always matches what runs.

Some verbs are **mode-locked**: `cmd` and `osint` exist only in the offensive
modes (`pentest`/`redteam`/`blueteam`); `forensics` exists only in `forensics`
mode. A mode-locked verb is hidden from `help` and refused at dispatch in any
other mode (the hard tool boundary is still the guard, not this UX gate).

> Examples below use the wrapped-shell spelling (`/skuggi …`). In the chat loop
> drop the `/skuggi`; in `skuggi-repl` use `/<verb>`.

## Agent

| Verb | Input | Effect |
|---|---|---|
| `ask` | `<prompt>` | Send a prompt to the agent (the default; bare text in the REPL) |
| `cmd` | `<query \| list \| <name> \| add \| edit <name> \| rm <name> \| suggest>` | The command cheatsheet (offensive modes only) — see below |
| `osint` | `<request>` | Run the autonomous OSINT reconnaissance loop (offensive modes) — see [osint-research.md](osint-research.md) |
| `research` | `<subject or instruction>` | Research a service / tech / company from public sources — see [osint-research.md](osint-research.md) |
| `forensics` | `<instruction>` | Run the read-only forensic examination loop over the case evidence (forensics mode) — see [engagement.md](engagement.md#forensics-mode) |

## Commands — the grouping verbs

### `show <what>` — inspect state

`config`, `provider`, `model`, `engagement`, `case`, `env` (runtime vars
`target`/`lhost`/`lport`/`wordlist`), `db` (ledger stats), `integrity` (verify the
timeline + custody tamper-evidence chains), `latency`, `sessions`, `tools
[filter]`, `memory`, `notes`, `loot`, `findings`, `coverage` (exercised
WSTG/ATT&CK ids vs the enabled taxonomy), `creds` (secrets masked), `footholds`
(pivot footholds, secrets masked), `history [n]`, `trace` (the worker's tool
calls this thread), `threads`, `status` (readiness + a session glance), `grants`
(active session approval grants).

### `set <what>` — change config / session state

| Noun | Input | Effect |
|---|---|---|
| `engagement` | `[<path>]` | Adopt an engagement root (cwd by default), scaffolding if absent |
| `case` | `[<path>]` | Adopt a forensics case root (cwd by default), scaffolding if absent |
| `provider` | `[<name>]` | Switch provider; with no name, run the guided provider + credential setup |
| `model` | `[<name>]` | Switch model; with no name, pick from the provider's curated list |
| `mode` | `<pentest\|redteam\|blueteam\|forensics>` | Switch the operating mode (prompt set) |
| `autonomous` | `[on\|off]` | Arm / disarm autonomous command execution |
| `config` | `<key> <value> \| <request>` | Set a setting, or a natural-language request |
| `scope` | `<request>` | Edit the engagement scope from a natural-language request |
| `target` | `<host>` | Set the current target host (the `${target}` var) |
| `listener` | — | Pick a listener interface + port (`lhost`/`lport`) |
| `wordlist` | `<path>` | Set the `${wordlist}` path |
| `thread` | `<id>\|new` | Start or switch a conversation thread |

### `add <what>` — record engagement data

`note <text>`, `loot <text>`, `cred <host> <service> <user> <secret>` (the secret
goes to the vault, never the chat), `foothold <host> <command|tunnel> <reach,csv>
<template>` (reachable-host commands route through it), `finding <severity|CVSS>
<title>`, `memory <entry>`.

### `remove <what>` — delete records

`memory <id> | all`, `grants` (revoke all session approval grants), `foothold`
(drop all registered pivot footholds).

## Engagement

| Verb | Input | Effect |
|---|---|---|
| `engagement` | `<setup \| threat-model>` | Run the scope setup wizard, or set the CVSS threat model — see [engagement.md](engagement.md) |

## Findings & reporting

| Verb | Input | Effect |
|---|---|---|
| `findings` | `<approve \| reject \| rescore>` | Review a finding (the listing is `show findings`) |
| `report` | `[pdf \| engagement [pdf] \| note <text>]` | Write a session or engagement report, or add a changelog note |
| `visualize` | — | Build an interactive HTML dashboard of the whole engagement |
| `replay` | `[list \| <session>]` | Reconstruct & view a session transcript |
| `review` | `[<session>]` | Private LLM review of a session (feedback for you, never client-facing) |

See [findings-and-reports.md](findings-and-reports.md) for the finding lifecycle,
CVSS scoring and the report pipeline.

## Harness

| Verb | Input | Effect |
|---|---|---|
| `doctor` | `[install <tool> \| install missing \| research <tool>]` | Probe host tools / runtimes / net tools; install a missing one on request |
| `login` | — | Log in to a ChatGPT account (OAuth) for the `chatgpt` provider |
| `ingest` | `<path>` | Index a file or directory into the retrieval store |
| `update` | — | Update skuggi (`git pull --ff-only`, then refresh this install) |
| `reconcile` | `[diff <file> \| <file> \| all]` | Update installed config from the packaged templates |
| `clear` | — | Clear the screen |
| `help` | `[<verb>]` | The verb reference (`help <verb>` lists a grouping verb's nouns) |
| `exit`, `quit` | — | Close cleanly |

**Interactive verbs need a loop.** `engagement setup`, a natural-language `set
config <request>` / `set scope <request>`, and `set provider`/`set model` with no
name prompt you back and forth, so they run in `skuggi-repl` or in the wrapped
shell's chat loop (a bare `/skuggi`). Invoked one-shot as `/skuggi engagement
setup`, they point you at the loop rather than half-running.

## `cmd`: the command cheatsheet (transparent, suggest-style)

`cmd` is a searchable cheatsheet of real CLI invocations
([src/skuggi/templates/commands.example.json](../src/skuggi/templates/commands.example.json),
seeded to `<config home>/commands.json`) — main use-cases for every
non-interactive tool skuggi knows (nmap, nikto, gobuster, ffuf, sqlmap,
ldapsearch, enum4linux-ng, nxc, hydra, john, hashcat, cewl, msfvenom, …). It is
available only in the offensive modes, and works in two steps:

- **`cmd <query>`** lists every entry whose name, tool or description contains the
  substring — `cmd nmap` shows all the nmap shorthands. `cmd` / `cmd list` shows
  the whole sheet.
- **`cmd <exact-name>`** *renders* that one entry, **prints the full command**,
  checks it against the engagement scope, records it (`proposed` in scope,
  `blocked` out of scope) and has the agent advise — it never executes.

`cmd suggest` asks the agent to suggest the most relevant cheatsheet entry for the
current situation; `cmd add` / `cmd edit <name>` / `cmd rm <name>` manage the sheet
(the interactive add/edit run inside the `/skuggi` chat loop or the REPL).

**Automatic, timestamped output.** Each tool declares an output flag and a
destination folder (`nmap → recon/nmap`, `gobuster`/`ffuf → recon/dirs`, `sqlmap →
recon/web`, crackers → `loot`, …). A rendered command therefore carries a
consistent output path:

```
cmd nmap-host
  $ nmap -sV -sC ${target} -oA recon/nmap/$(date +%Y-%m-%d_%H%M%S)_${target}_host
```

`$(date …)` and `${target}` are left **literal** so your shell expands them at run
time — the wrapped shell exports `target` from the engagement's primary host (a
sole allowed host/network, or the one you `set target <host>`). A few shipped
entries:

| Alias | Rendered (abridged) | Purpose |
|---|---|---|
| `nmap-host` | `nmap -sV -sC ${target} -oA recon/nmap/…_host` | service/version + default scripts |
| `nmap-full` | `nmap -p- -sV ${target} -oA recon/nmap/…_full` | all TCP ports with service detection |
| `gobuster-dir` | `gobuster dir -u ${target} -o recon/dirs/…_dir.txt` | directory brute-force (append `-w`) |
| `ffuf-dir` | `ffuf -u ${target} -of json -o recon/dirs/…_dir.json` | URL fuzzing (FUZZ keyword, append `-w`) |
| `sqlmap-url` | `sqlmap --batch -u ${target} --output-dir recon/web/…_url` | test a URL for SQL injection |
| `hashcat-ntlm` | `hashcat -m 1000 -a 0 -o loot/…_ntlm.txt` | crack NTLM with a wordlist |

The cheatsheet is just `<config home>/commands.json` — edit it by hand or with the
guided editor above.

## `memory`: standing operator preferences

The harness keeps a durable memory of how *you* like to work — which tool to
prefer when several would do, the language to write helper scripts in, how terse a
reply should be, reporting conventions. Remembered preferences are injected into
the planner, worker and critic every turn, so the agent follows your standing
instructions across threads and sessions.

They fill two ways:

- **Automatically, with your approval.** After a turn whose message reads like a
  standing directive (`always…`, `prefer…`, `from now on…`, `use X over Y`), the
  harness extracts the durable preference and *proposes* it. In the chat loop (or
  `skuggi-repl`) it previews the directive and asks you to approve before writing;
  a one-shot `/skuggi ask` only announces what it would remember and writes
  nothing (there is no loop to confirm against). One-off requests and
  target-specific facts are ignored. Turn the proposing off with `set config
  memory_auto false` (or `SKUGGI_MEMORY_AUTO=0`).
- **Manually.** `add memory <text>` stores one; `show memory` lists them with ids;
  `remove memory <id>` drops one; `remove memory all` empties the store.

Memory is **global** across engagements — a preference is about the operator, not a
target — and lives in the data home's `preferences.db`, separate from the ledger.
It is capped (`memory_max`, default 100): at the cap the automatic path refuses new
captures and warns rather than evicting anything, so you prune it yourself with
`remove memory`.
