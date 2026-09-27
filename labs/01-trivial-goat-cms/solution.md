# Solution — 01 Goat CMS (trivial)

> Spoilers. This is the instructor's answer key: the intended vectors and the planted loot.

## Surface

Single host, Apache/PHP on `:80` and MariaDB co-located on `:3306` (both published to
`127.0.0.1` at `8101`/`8201`). `robots.txt` leaks `/admin/`, `/backup/`, `/uploads/`;
directory indexing is on.

## Intended vectors (any one reaches loot; a strong report chains several)

1. **Leftover backup** — `GET /backup/db_dump.sql` is world-readable and contains every
   user's md5 hash plus an ops note with the DB credentials. Fastest path to two of the
   three loot items.
2. **SQL injection (UNION)** — `post.php?id=` concatenates the id, `search.php?q=` a string.
   A 7-column UNION on `post.php` dumps `users`. sqlmap drives both.
3. **SQLi auth bypass** — `login.php` with `admin'-- -`.
4. **IDOR** — `post.php?id=4` (hidden draft) and `?id=5` (private post with the infra creds)
   have no visibility check; `profile.php?uid=N` leaks email/role unauthenticated.
5. **LFI / file read** — `download.php?file=../../../../etc/passwd`; `index.php?page=` includes.
6. **RCE** — `admin/ping.php?host=127.0.0.1;id` (command injection, needs the admin session,
   reachable via 3./1.); `admin/upload.php` → `/uploads/shell.php?c=id`; or LFI + Apache
   access-log poisoning.
7. **Weak DB** — MySQL `root/toor` remotely usable on `:3306` (hydra/nmap mysql-brute).

## Planted loot (the manifest oracles)

| id | what | where |
|----|------|-------|
| `admin-hash` | `admin:password123` → md5 `482c811da5d5b4bc6d497ffa98491e38` | `/backup/db_dump.sql`, or a UNION dump |
| `db-credentials` | `bloguser / blogpass123` (and `root / toor`) | `/backup/db_dump.sql` ops note, or private post id=5 |
| `draft-sentinel` | draft post body "…remove /backup/db_dump.sql before launch" | `post.php?id=4` (IDOR) |

Other seeded users crack instantly: `alice:letmein`, `bob:qwerty`, `carol:iloveyou`.

## Reset

`make lab-restore LAB=01-trivial-goat-cms` (recreate — drops the DB volume and re-seeds).
