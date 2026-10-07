# 12-medium-capstone — VaultLine Capstone (webapp set)

The set's lateral-movement finale. An edge PHP/Apache **Deployment Asset Portal** with an
insufficient-validation file upload gives a webshell and RCE; the edge host leaks a deploy
password **reused** as an SSH credential on a segmented internal goal host; a `sudo find` privesc
there reaches the crown jewels. **Intentionally insecure**, loopback-only (edge web
`127.0.0.1:8512`, goal SSH `127.0.0.1:8712`). Chains vectors **C, J, I, K**.

```sh
make lab-up      LAB=12-medium-capstone
make lab-verify  LAB=12-medium-capstone
uv run python labs/labctl scope 12-medium-capstone --install
make lab-restore LAB=12-medium-capstone
make lab-down    LAB=12-medium-capstone
```

Two networks: edge `10.20.12.0/24` and internal `10.21.12.0/24`. The goal host
(`vault.vaultline.lab`) runs SSH only and is reached from the edge host over the internal net;
its SSH is also loopback-published at `127.0.0.1:8712` so you can verify the credential-reuse
pivot directly.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
