# Engagements, the scope boundary, autonomy, and modes

An engagement **is a directory**. You adopt a root with `set engagement <path>`
(the current directory by default); its `scope.json`, ledger, recon output and
reports live directly inside it. There is no `engagements/<name>/` wrapper. With
no engagement — no `scope.json` in the current directory and no
`SKUGGI_ENGAGEMENT_ROOT` override — skuggi runs agent-only (no scope, no ledger).

```sh
mkdir -p ~/work/acme-2026 && cd ~/work/acme-2026
skuggi
/skuggi set engagement          # adopt the current directory (scaffolds a scope.json)
/skuggi set engagement setup    # fill the scope in with the wizard
```

## The scope boundary

The authorized scope for one engagement is its workspace's `scope.json` (template:
[src/skuggi/templates/scope.example.json](../src/skuggi/templates/scope.example.json);
model: [src/skuggi/engagement/scope.py](../src/skuggi/engagement/scope.py)), loaded
at start and never committed:

```json
{
  "name": "acme-external-2026",
  "timezone": "Europe/Helsinki",
  "authorized_start": "2026-09-01T00:00:00+03:00",
  "authorized_end": "2026-12-31T23:59:59+02:00",
  "daily_windows": [{ "start": "09:00:00", "end": "17:00:00" }],
  "target_networks": ["192.0.2.0/24", "198.51.100.0/24"],
  "allowed_hosts": ["scanme.example.com"],
  "allowed_tools": ["nmap", "nikto", "curl", "gobuster", "sqlmap"],
  "allowed_methods": ["recon", "scan", "enumerate"],
  "allowed_ports": [],
  "stance": "cautious",
  "autonomous": false,
  "autonomous_ceiling": "active",
  "methodology": "phases",
  "taxonomies": ["wstg"],
  "threat_model": { "confidentiality_requirement": "high" },
  "osint": { "domains": ["acme.example.com"], "enabled_sources": ["crtsh", "dns"] },
  "rules_of_engagement": {
    "authorized_by": "Jane Client, CISO",
    "authorization_reference": "SOW-2026-014 (signed)",
    "excluded_hosts": ["prod-db.client.example"],
    "prohibited_actions": ["denial of service"]
  }
}
```

The fields fall into three kinds:

- **Enforced by the guard** — `target_networks`, `allowed_hosts`, `allowed_tools`,
  `allowed_methods`, `allowed_ports`, the time bounds (`authorized_start`/`_end` +
  `daily_windows`), and the `rules_of_engagement` **exclusions**
  (`excluded_networks`/`excluded_hosts`).
- **Advisory to the agent, never the guard** — `stance`, `methodology`,
  `taxonomies`, `threat_model` (CVSS Environmental), and the rest of
  `rules_of_engagement` (authorization metadata + operational posture rendered in
  the report header).
- **A separate dimension** — `osint` is the OSINT boundary (subjects + enabled
  sources), its own guard; see [osint-research.md](osint-research.md).

Optional fields can be omitted: empty time bounds mean no time window at all;
empty `allowed_ports` means every port is allowed (set it to gate ports); absent
`threat_model`/`osint`/`rules_of_engagement` disables that dimension.

### How a command is checked

Every command the agent proposes is parsed and checked by a single guard
(`check_command` in [src/skuggi/engagement/guard.py](../src/skuggi/engagement/guard.py)).
The rule is conservative — **anything the guard cannot prove in scope is denied**:

1. **Exclusions first** — a command touching an `excluded_networks`/`excluded_hosts`
   target is denied even if it also matches an allow-list (deny wins).
2. The binary must be a **recognized tool**, invoked by bare name — a pathed
   `argv[0]` (`/usr/bin/nmap`, `./nmap`) is denied, since authorization keys on the
   basename. A **transport/pivot tool** (ssh/proxychains/…) invoked directly is
   denied; pivoting goes through a registered foothold (`add foothold`).
3. The tool must be in **`allowed_tools`** and its registry **method** in
   **`allowed_methods`**.
4. The current time must be inside the **date window** and a **daily clock window**.
5. Every extracted **target** must be inside an allowed network/host — a target
   expression the guard cannot enumerate (an open range, an `-iL` target file) is
   denied.
6. When `allowed_ports` is set, every **port** the command names must be in it; an
   unparseable port spec is denied.
7. Every **data-file path** (wordlist/user/cred lists) is confined to the workspace
   (or a configured `wordlist_roots` location) — the file reaches the tool, its
   contents never reach the model.

`allowed_methods` is coarse by design: each registry entry declares one static
method (`nmap`→`scan`, `curl`→`recon`), so it gates tool *categories* and largely
reinforces `allowed_tools` — it does not distinguish `nmap -sn` from `nmap -A`.

### The setup wizard

`set engagement setup` runs a grouped, step-by-step wizard (Identity, Authorization,
Schedule, Targets, Capabilities, Approach) with a horizontal step bar. Methods,
methodology, taxonomies and stance are dropdowns/checklists; timezone and tools
autocomplete (in the REPL); the authorized window is optional (a blank start/end
means no time bound). It validates the answers, writes `scope.json` into the
active engagement root, and **hot-reloads** the boundary into the running session —
no restart. A rejected answer re-asks only the field that failed; a blank keeps the
current value when editing; `Ctrl-C`/`Esc` cancels. A natural-language `set
engagement scope <request>` edits the authorization fields the same way, and any
single field can be changed with `set engagement <param>` (e.g. `set engagement
methodology ptes`, `set engagement osint`).

## Suggest by default, autonomous on request

The worker returns a structured response; when it proposes a `command`, the
executor node sends it through the engagement guard and never runs a blocked one.
For an in-scope command:

- **suggest mode (default, `autonomous: false`)** — records the command as
  `proposed` and hands it back for you to run by hand.
- **autonomous mode (`autonomous: true` in the scope, or `set engagement autonomous on`)** —
  executes it (`shell=False`, argv exec'd directly, output byte-capped, wall-clock
  timeout `command_timeout_s`), records the result, and feeds it back to the worker
  for the next step (bounded by `max_command_rounds`). The prompt shows `!` and the
  banner shows autonomous ON while armed.

Autonomy is a **risk ceiling, not a switch.** Each command carries a risk tier
(recon/active/… via the tool registry); even with autonomous armed, a command
**above** `autonomous_ceiling` (default `active`) is held `proposed` for you to run
by hand — the deterministic "manual escalation" gate
([src/skuggi/engagement/risk.py](../src/skuggi/engagement/risk.py),
`executor._run_or_propose`). Conservative by default: recon/scans auto-run,
brute-force/crack/exploit escalate. The ceiling only ever holds back; it never
widens authority.

**Execution backend.** An agent-cleared command runs through a pluggable backend
(`execution_backend`): `host` (default) is a hardened host subprocess; `container`
runs each tool in a throwaway docker/podman container (read-only rootfs, caps
dropped, resource caps, workspace-only writable, network `none` unless you set an
egress-filtered network). See [configuration.md](configuration.md#execution-backend).

Blocked, proposed and executed commands are all persisted with timestamps; the
ledger also records each command's risk tier and the authority under which it ran.

## The per-engagement workspace

The root you adopt holds the workspace directly
([src/skuggi/engagement/workspace.py](../src/skuggi/engagement/workspace.py)),
created on adoption:

```
<engagement root>/
  scope.json            # the engagement boundary
  env.json              # runtime command vars (target / lhost / lport / wordlist)
  findings/             # per-finding artefacts (structured records are in the ledger)
  notes/notes.md        # `add note` — timestamped operator notes
  recon/nmap/  recon/nuclei/  recon/dirs/  recon/domains/  recon/web/   # cmd output
  osint/                # OSINT loop output
  research/             # research loop briefings
  inputs/               # operator-supplied wordlists / user & credential lists (fed to tools by path)
  evidence/             # files pulled from a target (downloads, documents)
  loot/                 # cracked hashes, captured creds, payloads
  loot/loot.md          # `add loot` — timestamped loot log
  reports/              # report output
  scripts/  tests/
  ledger.db             # this engagement's ledger (hash-chained; see findings-and-reports.md)
  .vault.db             # 0600 secret vault for reversible redaction (never committed)
  .custody.key          # HMAC key for the forensics chain of custody
```

The folder names are configurable
([src/skuggi/templates/layout.example.json](../src/skuggi/templates/layout.example.json)).
Keep your engagement roots out of version control — they hold the ledger and loot.

## Modes

`set mode pentest|redteam|blueteam` swaps the planner/worker/critic prompt set
([src/skuggi/agent/prompts.py](../src/skuggi/agent/prompts.py)); the graph and guard
are identical across these three. Set the default with `SKUGGI_MODE`.

### forensics mode

`set mode forensics` is different: a strictly read-only, engagement-free discipline
for examining local evidence. It binds to a **case** (a directory, adopted with
`set case <path>`) instead of an engagement, with its own separate ledger
(`case.db`). Drop evidence into the case `evidence/` directory and run `forensics`
to examine it: the loop hashes each artifact, runs an in-process analyzer battery
(strings, hexdump, entropy, magic-type, encoding/decoding, log parsing, keyed
decryption, and — with the `forensics` extra — OCR and AI vision over images),
records a chain-of-custody procedure log, and writes a cited Markdown/PDF case
report. Nothing is ever written to or executed from the evidence; the forensic tool
surface is a built-in read-only allow-list and every positional path is confined to
the case. Offensive verbs (`cmd`, `osint`) are unavailable in this mode, and every
finding the examiner cannot tie to collected evidence is marked speculative.

OCR and keyed decryption need the optional `forensics` extra (installed by `make
install`); OCR also needs the system `tesseract` binary (`brew install tesseract` /
`apt-get install -y tesseract-ocr`), which `skuggi-doctor` reports on. AI vision
(`forensics_vision`, on by default) runs only on a vision-capable provider
(`openai`/`anthropic`) and is skipped gracefully otherwise.
