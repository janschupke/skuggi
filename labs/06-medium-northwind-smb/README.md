# 06 · Northwind SMB — medium

A Samba file server (guest-readable share with a KeePass vault) + a Linux pivot host. The
vault master is **not in rockyou** — derive it from the naming convention in the HR notes,
crack it, reuse the SSH creds, and pivot to the customer contracts. Read
[briefing.md](briefing.md); [solution.md](solution.md) is the key.

> ⚠️ Intentionally insecure. Loopback-only (SMB 8106, SSH 8206). Never expose it.

```sh
make lab-up     LAB=06-medium-northwind-smb
make lab-verify LAB=06-medium-northwind-smb
uv run python labs/labctl scope 06-medium-northwind-smb --install
make lab-restore LAB=06-medium-northwind-smb
make lab-wipe    LAB=06-medium-northwind-smb
```
