# One Debian server, two states. Both start from the same pinned snapshot so the only differences
# are the misconfigurations (baseline) and the hardening plus patching (hardened).
#   docker build -f target/Dockerfile --target baseline -t scm-target:baseline target
#   docker build -f target/Dockerfile --target hardened -t scm-target:hardened target
FROM debian:bookworm-20240110 AS baseline

ENV DEBIAN_FRONTEND=noninteractive
# The snapshot's own package versions, no upgrade: this is the "unpatched" estate.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo lynis inetutils-telnetd procps \
 && rm -rf /var/lib/apt/lists/*

# Deliberate misconfigurations a real audit finds often. Lab only.
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && useradd -m -s /bin/bash legacy && passwd -d legacy && usermod -aG sudo legacy \
 && useradd -o -u 0 -g 0 -M -s /bin/bash backup0 \
 && chmod 644 /etc/shadow \
 && mkdir -p /opt/app && echo "db_password=placeholder-not-a-real-secret" > /opt/app/config.ini && chmod 666 /opt/app/config.ini

CMD ["sleep", "infinity"]


FROM baseline AS hardened
COPY harden.sh /tmp/harden.sh
RUN sh /tmp/harden.sh && rm /tmp/harden.sh
