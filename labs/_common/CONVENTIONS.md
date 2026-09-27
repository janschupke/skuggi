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

Prefer `restore.strategy: "reseed"` (exec a seed script in the container — fast, keeps the
engagement) when the target's mutable state is a DB/files that a script can reset in place.
Fall back to `"recreate"` (drop volumes + re-up) when a clean volume is the only reliable
reset (e.g. the trivial lab's first-boot MariaDB seed).
