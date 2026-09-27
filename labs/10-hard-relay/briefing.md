# Engagement brief — RELAY spool service

**Tier:** hard · **Targets:** `relay.control.lab` (`10.13.10.10`), `mgmt.control.lab` (`10.13.10.20`) · **Scope net:** `10.13.10.0/24`

## Scenario

A financial back-office runs an old in-house "RELAY" spool service and a small web console
to manage it. Nobody remembers exactly how the RELAY protocol works, and the vendor is gone.
The client wants to know whether either service can be abused to reach the custody records.

## Rules of engagement

- In scope: `10.13.10.0/24` — the RELAY service (`127.0.0.1:8210`) and the management console
  (`127.0.0.1:8110`).
- Probing and reversing the custom protocol is in scope. No DoS.

## Objective

Work out the RELAY protocol, find the flaw, and chain it to the console. Recover, with
evidence:

- how the **custom TCP service** speaks (its banner and verbs),
- a **file-disclosure** flaw and any **credentials** it leaks,
- the **custody vault** records behind the management console's admin area.

A generic port scan will not identify the RELAY service — you will have to talk to it. The
console offers a legacy client that is worth reading.
