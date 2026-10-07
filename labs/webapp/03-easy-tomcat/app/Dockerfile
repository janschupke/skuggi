# Orionline Deploy — Apache Tomcat 9 / JDK 11, deliberately misconfigured.
#
# What makes it vulnerable:
#   1. The bundled Manager + Host-Manager apps are re-enabled and their
#      RemoteAddrValve lock is commented out, so /manager/html answers from the
#      whole lab network instead of only loopback.
#   2. conf/tomcat-users.xml grants manager-gui + manager-script to weak,
#      guessable accounts (tomcat:s3cret, admin:admin).
#   3. Tomcat runs as the unprivileged `deploy` user, but a planted sudo
#      misconfig (NOPASSWD on a world-writable release script) turns that
#      foothold into root.
FROM tomcat:9-jdk11

# sudo backs the planted privesc; curl backs the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash deploy

# The official image ships the bundled webapps disabled under webapps.dist.
# Restore ROOT (the fingerprintable landing page), the Manager app and the
# Host-Manager app into the live webapps dir.
RUN cp -a /usr/local/tomcat/webapps.dist/ROOT         /usr/local/tomcat/webapps/ROOT \
    && cp -a /usr/local/tomcat/webapps.dist/manager      /usr/local/tomcat/webapps/manager \
    && cp -a /usr/local/tomcat/webapps.dist/host-manager /usr/local/tomcat/webapps/host-manager

# Weak Manager credentials (manager-gui + manager-script).
COPY conf/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml

# Drop the RemoteAddrValve so the Manager/Host-Manager UIs answer off-box.
COPY conf/manager-context.xml      /usr/local/tomcat/webapps/manager/META-INF/context.xml
COPY conf/host-manager-context.xml /usr/local/tomcat/webapps/host-manager/META-INF/context.xml

# Planted "after access" material.
COPY privesc/credentials.properties /opt/orionline/config/credentials.properties
COPY privesc/deploy-release.sh      /opt/orionline/bin/deploy-release.sh
COPY privesc/deploy-sudoers         /etc/sudoers.d/deploy

# Permissions: Tomcat tree owned by the unprivileged runtime user; the sudoers
# file locked 0440 (sudo refuses a writable policy) while the release script it
# authorises is world-writable 0777 — that is the privesc.
RUN chown -R deploy:deploy /usr/local/tomcat \
    && chmod 0644 /usr/local/tomcat/conf/tomcat-users.xml \
    && chmod 0644 /opt/orionline/config/credentials.properties \
    && chmod 0777 /opt/orionline/bin/deploy-release.sh \
    && chown root:root /opt/orionline/bin/deploy-release.sh /etc/sudoers.d/deploy \
    && chmod 0440 /etc/sudoers.d/deploy

USER deploy

EXPOSE 8080
