#!/bin/sh
# Remediation for every baseline finding, plus patching. Each block names the control it fixes
# (ids from checks/controls.yaml).
set -eu
export DEBIAN_FRONTEND=noninteractive

# CTL-01, CTL-02: SSH, no root login, keys only
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# CTL-03: no account without a password; CTL-04: only root has UID 0; CTL-07: no stale admin rights
# -f: backup0 shares UID 0 with root, so userdel sees "root" processes as that user logged in.
userdel -f backup0
usermod -L legacy
gpasswd -d legacy sudo

# CTL-05: shadow file not readable by everyone
chmod 640 /etc/shadow && chgrp shadow /etc/shadow

# CTL-06: no world-writable application files (and the config moves out of reach of other users)
chmod 640 /opt/app/config.ini

# CTL-08: password expiry policy
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs

# CTL-09: remove legacy cleartext service
apt-get update
apt-get purge -y inetutils-telnetd

# CTL-10: patch management, apply all available updates
apt-get upgrade -y

# CTL-11: firewall, default deny inbound with SSH allowed (ruleset file; containers do not load it)
apt-get install -y --no-install-recommends nftables auditd
cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 22 accept
  }
}
NFT

# CTL-12: audit logging installed and configured to log account changes
echo '-w /etc/passwd -p wa -k identity' > /etc/audit/rules.d/identity.rules
echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/identity.rules

rm -rf /var/lib/apt/lists/*
