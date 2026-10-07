# Lab authoring conventions

Shared rules every lab under `labs/NN-*/` follows. `_common/` holds no runnable code (it is
excluded from ruff/mypy); it is the authoring contract.

## Isolation (hard requirements)

- **No external/third-party calls at runtime.** LocalStack stands in for AWS; Samba for a
  Windows DC; every cloud-metadata/IMDS endpoint is a local mock container. Build-time base
  images from Docker Hub are fine.
- **Loopback-only publishing.** Every published port binds `127.0.0.1`. Never `0.0.0.0`.
- **One network per lab** (two for segmented labs), from private / TEST-NET ranges. Segmented
  labs keep the goal host on the internal-only network, unpublished — reachable only by
  pivoting through an edge host.

## Naming / ports

- Compose `name: skuggi-lab-NN…`; containers `skuggi-NN-<svc>`; built images `skuggi-lab-NN-<svc>`.
- HTTP → `81NN`; auxiliary services → `82NN`, `83NN` (NN = the two-digit lab number).
- The scope's `name` matches the lab id, so `labctl scope --install` and
  `SKUGGI_ENGAGEMENT=<id>` line up.

## Difficulty

- **trivial / easy:** standard, scanner-visible vectors. Easy still requires ~2 chained steps
  and a small pivot in thinking; default wordlists mostly work.
- **medium / hard:** deliberately non-obvious. No default-seclist path (invent endpoint/share
  names, discoverable only via leaked specs/bundles/source), no textbook single vector
  (prefer logic flaws, chains, and network segmentation), and any crackable secret must be
  derivable from **in-lab** context, never from stock `rockyou`.

## Planted data

Every lab plants realistic loot a report can cite — password hashes, customer PII, signed
contracts, API/signing keys, SSH/KeePass material. Declare each as a `manifest.json` `loot[]`
entry with a stable `fingerprint` so `labctl verify` can confirm a pristine restore.

## Restore

`restore.strategy: "recreate"` (drop volumes + re-up) is the norm across the range — a clean
volume is the most reliable reset, and every lab currently uses it. `labctl restore` keeps
your `./engagements/<id>` either way. `"reseed"` (exec a seed script in the container —
faster, no teardown) is also supported by `labctl` for a target whose mutable state a script
can reset in place; it is available if a future lab wants it, but none relies on it today.

## Sets

The flat `labs/NN-*` dirs are the **base** set. A second, framework-coverage **webapp** set
lives one level deep under `labs/webapp/NN-*` with its own port band (`85/86/87NN`), subnet
block (`10.20/10.21.NN.0/24`) and compose prefix (`skuggi-webapp-NN`); see
[`../webapp/README.md`](../webapp/README.md). `labctl` discovers both and groups `make
lab-list` by category; the category is derived from layout (flat = `base`, else the
subdirectory name).
