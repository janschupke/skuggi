# skuggi practice range — webapp set

Twelve framework-focused web-application engagement labs, a **separate set** from the base
range in [`../`](../README.md). Where the base labs climb a trivial→hard ladder of mixed
scenarios, this set prioritises **framework × attack-vector coverage** at easy/medium
difficulty: one lab per web framework plus a lateral-movement capstone. They are *example*
labs — coverage and reliability over realistic complexity — but every lab produces **real
reportable findings** (SQLi auth bypass, dumped PII, cracked hashes, uploaded webshells,
exfiltrated files, SSH pivots), not single-flag paths.

> ⚠️ Every lab is **intentionally insecure** and loopback-only. Nothing calls out at runtime.
> Run only on a machine you control, for authorized practice.

`labctl` discovers these automatically (they live under `labs/webapp/`, one category level
deep) and `make lab-list` groups them under `== webapp ==`. Drive them exactly like the base
labs:

```sh
make lab-list                               # base + webapp, grouped by category
make lab-up      LAB=01-easy-php-plain       # build + start (loopback-only)
make lab-verify  LAB=01-easy-php-plain       # assert the planted loot seeded
make lab-restore LAB=01-easy-php-plain       # revert the TARGET to pristine
make lab-wipe    LAB=01-easy-php-plain       # nuke the target AND ./engagements/<lab>
make lab-down    LAB=01-easy-php-plain       # stop, keep planted data
uv run python labs/labctl scope 01-easy-php-plain --install   # drop scope.json into ./engagements/
```

## Webapp-set conventions (on top of `../_common/CONVENTIONS.md`)

Its own port band, subnet block and compose prefix keep it from ever colliding with a base
lab brought up alongside it:

- **Dir:** `labs/webapp/NN-<tier>-<framework>/`, `NN` = `01`…`12` (this set restarts the
  numbering; the full lab **id** still differs from every base id).
- **Compose:** `name: skuggi-webapp-NN`; containers/images `skuggi-webapp-NN-<svc>`
  (base uses `skuggi-lab-NN`).
- **Ports (loopback-only, `127.0.0.1`):** HTTP `85NN`; auxiliary services `86NN`/`87NN`.
- **Subnets:** primary `10.20.NN.0/24`; a second internal net for segmented/pivot labs
  `10.21.NN.0/24`.
- **Restore:** `recreate` (drop volume + first-boot reseed).
- **Planted secrets** are deliberately fake-but-realistic; the `detect-private-key`
  pre-commit hook excludes `^labs/(webapp/)?[0-9]`.

## The ladder

Vectors: **A** SQLi→login · **B** wordlist brute login · **C** upload→RCE · **D** path
traversal exfil · **E** db-dump weak/crackable hash · **F** db-dump customer PII · **G** IDOR
(query param + route) · **H** stored XSS · **I** cred-reuse → SSH lateral · **J** framework/web
exploit → revshell · **K** easy privesc after access.

| NN | lab | tier | framework / stack | port | vectors |
|----|-----|------|-------------------|------|---------|
| 01 | `01-easy-php-plain`   | easy   | Apache + PHP + MariaDB        | 8501 | A,E,F |
| 02 | `02-easy-wordpress`   | easy   | WordPress + MariaDB           | 8502 | B,E,J |
| 03 | `03-easy-tomcat`      | easy   | Tomcat (Manager, weak creds)  | 8503 | B,J,K |
| 04 | `04-easy-node`        | easy   | Node/Express + SQLite         | 8504 | D,G,H |
| 05 | `05-easy-django`      | easy   | Django + Postgres             | 8505 | G,F,H,E |
| 06 | `06-medium-laravel`   | medium | Laravel + MySQL               | 8506 | C,J,K |
| 07 | `07-medium-symfony`   | medium | Symfony + Postgres            | 8507 | A,D,G |
| 08 | `08-medium-rails`     | medium | Rails + Postgres + SSH pivot  | 8508 | G,I,K |
| 09 | `09-medium-dotnet`    | medium | ASP.NET Core + Postgres       | 8509 | A,D,J |
| 10 | `10-medium-drupal`    | medium | Drupal + planted vuln module  | 8510 | A,F,K |
| 11 | `11-medium-moodle`    | medium | Moodle + MariaDB              | 8511 | H,G,F |
| 12 | `12-medium-capstone`  | medium | edge web + segmented SSH host | 8512 | C,J,I,K |

Each lab is the standard shape (`manifest.json`, `scope.json`, `briefing.md`, `solution.md`,
`README.md`, `docker-compose.yml` + build contexts). `01-easy-php-plain` is the reference
implementation for the set.
