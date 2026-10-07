# 09-medium-dotnet — NetLedger (webapp set)

ASP.NET Core 8 accounting API on Postgres (Npgsql). **Intentionally insecure**, loopback-only
(`127.0.0.1:8509`). Covers: SQLi auth bypass + data dump, path-traversal secrets exfiltration,
admin-diagnostics command injection → RCE/revshell.

```sh
make lab-up      LAB=09-medium-dotnet
make lab-verify  LAB=09-medium-dotnet
uv run python labs/labctl scope 09-medium-dotnet --install
make lab-restore LAB=09-medium-dotnet
make lab-down    LAB=09-medium-dotnet
```

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
