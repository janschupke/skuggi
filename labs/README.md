# skuggi practice range

Self-contained pentest engagement exercises with **real reportable surface and planted loot**
(hashes, credentials, contracts, customer data) — not single-flag paths. Drive them with
skuggi like a real engagement; manage them with `labctl`.

Two sets, grouped by category in `make lab-list`:

- **base** — the ten flat `labs/NN-*` labs on a trivial→hard ladder of mixed scenarios
  (below).
- **webapp** — twelve framework-focused labs under [`webapp/`](webapp/README.md)
  (plain PHP, WordPress, Tomcat, Node, Django, Laravel, Symfony, Rails, .NET, Drupal, Moodle,
  and a lateral-movement capstone), at easy/medium difficulty, aimed at framework ×
  attack-vector coverage.

The rest of this page documents the **base** set.

> ⚠️ Every lab is **intentionally insecure**. Run only on a machine you control, for
> authorized practice. All ports bind to `127.0.0.1` only. Nothing calls a third-party or
> external API **at runtime** — the "cloud" lab uses LocalStack, the "AD/SMB" lab uses Samba,
> and every metadata/IMDS endpoint is a local mock. (Base images are pulled from registries
> at build time; lab 01's **optional** WireGuard overlay is the one runtime image fetched
> from a third party.)

Full guide (topology, credentials, the `labctl` workflow, per-lab intent): [../docs/labs.md](../docs/labs.md).
This is separate from the frozen automated-test target in `tests/e2e/fixtures/lab/`, which
CI drives and which never changes as these labs evolve.

The ten labs, their tiers and their non-obvious hooks are listed in the full guide,
[../docs/labs.md](../docs/labs.md#the-ladder) — trivial/easy use standard, scanner-visible
vectors; medium and hard are deliberately non-obvious (no default-seclist path, no textbook
single vector, segmented networks).

## Using labctl (from the repo root)

```sh
make lab-list                              # every lab, tier, ports, up/down
make lab-up      LAB=01-trivial-goat-cms   # build + start (loopback-only)
make lab-verify  LAB=01-trivial-goat-cms   # assert the planted loot seeded
make lab-restore LAB=01-trivial-goat-cms   # revert the TARGET to pristine, keep your work
make lab-wipe    LAB=01-trivial-goat-cms   # nuke the target AND ./engagements/<lab>
make lab-down    LAB=01-trivial-goat-cms   # stop, keep planted data

uv run python labs/labctl scope 01-trivial-goat-cms --install   # drop scope.json into ./engagements/
```

## Anatomy of a lab

```
NN-tier-name/
  manifest.json     # machine-readable: tier, networks, ports, health, restore, loot[]
  scope.json        # drop-in skuggi EngagementConfig authorizing exactly this lab
  briefing.md       # the client scenario + rules of engagement + objective
  solution.md       # the answer key: intended chain + loot manifest
  docker-compose.yml
  <build contexts>  # web/, api/, db/, services/ ...
```

`labctl` reads only `manifest.json`; `tests/unit/test_labs_static.py` validates every
manifest and scope offline, so a malformed lab fails `make check` without booting docker.

## Conventions (see `_common/CONVENTIONS.md`)

- **One isolated network per lab** (two for segmented labs), from private/TEST-NET ranges so
  a stray route can never hit real infrastructure. In a segmented lab the goal host lives on
  the internal-only network, unpublished.
- **Loopback-only published ports**: HTTP on `81NN`, auxiliary services on `82NN`/`83NN`
  (NN = lab number). Only one lab is expected up at a time; distinct ports let two coexist.
- **Unique compose project + image names** per lab (`skuggi-lab-NN…`) so no two stacks
  collide on names. One caveat: lab 01 and the e2e fixture both default to the `192.0.2.0/24`
  bridge, so those two cannot be up simultaneously (override lab 01 with `LAB_SUBNET=` if you
  need both). Every other lab has its own subnet.
- **Planted loot with stable fingerprints** in `manifest.json`, so `labctl verify` proves a
  restore re-seeded and a future scoring harness can auto-grade.
