# 03-easy-tomcat — Orionline Deploy (webapp set)

Apache Tomcat 9 (JDK 11) with the **Manager app enabled and reachable from the network**,
its RemoteAddrValve lock removed and guarded only by **weak credentials**. **Intentionally
insecure**, loopback-only (`127.0.0.1:8503`). Covers: wordlist brute of the Manager login,
malicious-WAR deploy → RCE → reverse shell, and an easy sudo privesc to root.

```sh
make lab-up      LAB=03-easy-tomcat
make lab-verify  LAB=03-easy-tomcat
uv run python labs/labctl scope 03-easy-tomcat --install
make lab-restore LAB=03-easy-tomcat
make lab-down    LAB=03-easy-tomcat
```

This is the one lab in the set with a **real, clean path** (Tomcat Manager → WAR deploy), not
a planted application bug. A small `wordlist.txt` ships next to this README — the weak Manager
password hides among the decoys.

Scenario and objective: [briefing.md](briefing.md). Answer key: [solution.md](solution.md).
Part of the **webapp** set — see [../README.md](../README.md).
