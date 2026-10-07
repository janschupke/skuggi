# Engagement brief — LearnHub learning-management portal

**Tier:** medium · **Set:** webapp · **Target:** `app.learnhub.lab` (`10.20.11.20`) · **Scope net:** `10.20.11.0/24`

> **On macOS** reach it at the loopback-published port `127.0.0.1:8511` — Docker Desktop
> doesn't route container IPs; the IP above is the Linux/direct-routing view.

## Scenario

LearnHub is a Moodle-based learning-management system a mid-size training provider runs for
its students and instructors. Course material, forums and student profiles all live in the
portal. Ahead of onboarding a new cohort, LearnHub's operations team wants a light
penetration test of the live LMS.

To let you work as a real user would, the client has issued you a **low-privilege student
test account** (`jrowan` — password in your handover note). Everything else you reach from
that account, or without any account, is what they want assessed.

## Rules of engagement

- In scope: `10.20.11.0/24` — the Moodle app (`app.learnhub.lab`) and its database host
  (`db.learnhub.lab`).
- The app is published to `127.0.0.1:8511` for your convenience.
- No destructive writes or DoS. Reading, enumerating, proving access and demonstrating a
  payload are in scope; don't deface courses or delete student data.

## Objective

The client's real worry is **student-data exposure and account/session compromise**. Produce
findings that recover, with evidence:

- any place where **user-supplied HTML/script is stored and rendered** back to other users
  (a session-stealing stored-XSS path),
- any **broken access control** that lets one user read another user's data by **changing an
  id in the URL** (IDOR), and
- any **student PII or credential material** (profiles, emails, password hashes) an attacker
  could **exfiltrate from the database** and whether the hashes are **reusable** (crackable
  offline).

Moodle is a large, real application — enumerate its endpoints, note the framework version,
and tie each finding to the concrete URL or table that proves it.
