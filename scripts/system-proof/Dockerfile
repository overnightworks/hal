# A throwaway Ubuntu 26.04 with systemd as PID 1, dbus and polkitd, for the container proof of `hal setup`'s
# system step (#40). cloudflared comes from Cloudflare's apt repository; its config names a fake tunnel id, and
# the credential beside it is a dummy that only lets the unit try to start. No real secret is ever in here.
# python3 and python3-apt supply Ansible's interpreter and apt module binding in this fixture.
# openssl and python3-aiosmtpd are for the mail cells (D1-D8): a test CA and a mail sink; msmtp itself comes from the apply.
# rsyslog, postfix (preseeded to "No configuration", so /etc/postfix/main.cf is absent as on the PC, where its sendmail
# logs a fatal every night) and kerneloops are Ubuntu's own packages as the PC has them, for the cells R0-R7 (#422): the
# apply purges rsyslog, and the proof checks what that leaves. docker.io is the engine itself, with the root:docker socket the
# agents' refusal cells (A1-8, A1-9) need and the cells DK1-DK8 drive; docker-buildx reports the build cache limit of DK8; docker-compose-v2 is the `docker compose` of DK6;
# busybox-static makes the rootfs it imports, so no image is pulled at proof time.
# 26.04 makes sudo-rs the default `sudo`. The image carries both, and the `sudo` alternative defaults to classic sudo
# (/usr/bin/sudo.ws); the sudo stages pin their own variant.
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
# The 26.04 archive no longer carries kerneloops; the PC keeps the 24.04 package it was upgraded with, so the image
# installs that exact .deb from the archive pool for cell R7.
ARG KERNELOOPS_DEB_URL=https://archive.ubuntu.com/ubuntu/pool/main/k/kerneloops/kerneloops_0.12+git20140509-6ubuntu8_amd64.deb
ARG KERNELOOPS_DEB_SHA256=96a71bbc5fcffb6fbf623db34bf1c9ac5484f5263ba1c5ea479d82384de27a7e
# Ansible dates the cache by its success stamp or the lists directory, so empty indexes must also be stale.
# The base image's policy-rc.d (exit 101) is removed last, as on the PC, so a package installed in the proof starts its service.
RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        busybox-static \
        ca-certificates \
        curl \
        dbus \
        docker-buildx \
        docker-compose-v2 \
        docker.io \
        expect \
        git \
        gnupg \
        openssl \
        polkitd \
        postfix \
        python3 \
        python3-aiosmtpd \
        python3-apt \
        rsyslog \
        sudo \
        sudo-rs \
        systemd \
        systemd-sysv \
    && update-alternatives --set sudo /usr/bin/sudo.ws \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --output /tmp/kerneloops.deb "$KERNELOOPS_DEB_URL" \
    && echo "$KERNELOOPS_DEB_SHA256  /tmp/kerneloops.deb" | sha256sum --check --strict \
    && apt-get install -y --no-install-recommends /tmp/kerneloops.deb \
    && rm /tmp/kerneloops.deb \
    && mkdir -p --mode=0755 /usr/share/keyrings \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --output /usr/share/keyrings/cloudflare-main.gpg https://pkg.cloudflare.com/cloudflare-main.gpg \
    # Cloudflare's repository has no 26.04 codename (404 for resolute); `any` is the one it serves for every release.
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
        > /etc/apt/sources.list.d/cloudflared.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflared \
    && rm -rf /var/lib/apt/lists/* /var/lib/apt/periodic/update-success-stamp \
    && touch -d @0 /var/lib/apt/lists \
    && rm -f /usr/sbin/policy-rc.d \
    && install -D /bin/busybox /tmp/rootfs/bin/busybox \
    && tar --directory /tmp/rootfs --create --file /usr/local/share/proof-rootfs.tar . \
    && rm -rf /tmp/rootfs

COPY --from=ghcr.io/astral-sh/uv:0.10.9 /uv /uvx /usr/local/bin/

# `tester` is the operator: in the sudo and docker groups (hal reads `docker info` as the operator, before the password), its password set per run by run.sh. `bystander` is any other user.
ARG FAKE_TUNNEL_ID=00000000-0000-4000-8000-000000000000
RUN mkdir -p /etc/cloudflared \
    && printf 'tunnel: %s\ncredentials-file: /etc/cloudflared/%s.json\n' \
        "$FAKE_TUNNEL_ID" "$FAKE_TUNNEL_ID" > /etc/cloudflared/config.yml \
    && printf '{"AccountTag":"fake","TunnelSecret":"ZmFrZQ==","TunnelID":"%s"}\n' \
        "$FAKE_TUNNEL_ID" > "/etc/cloudflared/$FAKE_TUNNEL_ID.json" \
    && chmod 600 "/etc/cloudflared/$FAKE_TUNNEL_ID.json" \
    && useradd --create-home --shell /bin/bash --groups sudo,docker tester \
    && useradd --create-home --shell /bin/bash bystander \
    && printf '%s\n' '[Unit]' 'Description=another unit for the polkit cells' \
        '[Service]' 'ExecStart=/bin/sleep infinity' \
        '[Install]' 'WantedBy=multi-user.target' \
        > /etc/systemd/system/proof-other.service \
    && systemctl enable proof-other.service

# The wheel of this checkout and edge's tunnel/ files, all staged by run.sh.
COPY context/ /proof/
RUN install -d -o tester -g tester /home/tester/srv/hal \
    && cp -r /proof/tunnel /home/tester/srv/hal/tunnel \
    && chown -R tester:tester /home/tester/srv \
    && chmod +x /proof/drive.sh /proof/terminal.exp

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
