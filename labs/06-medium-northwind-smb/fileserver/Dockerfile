# Build the planted KeePass vault with pykeepass.
FROM python:3.12-slim AS kdbx
RUN pip install --no-cache-dir pykeepass==4.1.0
WORKDIR /b
COPY build_kdbx.py ./
RUN python build_kdbx.py /b/passwords.kdbx

# Samba file server with a guest-readable public share.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba \
 && rm -rf /var/lib/apt/lists/*
COPY smb.conf /etc/samba/smb.conf
COPY share/ /srv/samba/public/
COPY --from=kdbx /b/passwords.kdbx /srv/samba/public/IT/passwords.kdbx
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 445
ENTRYPOINT ["/entrypoint.sh"]
