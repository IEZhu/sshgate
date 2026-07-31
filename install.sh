#!/bin/bash
# sshgate installer.  Run as root:   sudo DOMAIN=your.host ./install.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="${DOMAIN:-example.com}"
PY="$(command -v python3)"

echo "==> service user"
id sshgate &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin sshgate

echo "==> directories"
install -d -m 755 /opt/sshgate
install -d -m 750 -o sshgate -g sshgate /etc/sshgate
install -d -m 750 -o sshgate -g sshgate /var/log/sshgate
install -d -m 700 /var/lib/sshgate/opens

echo "==> app, helper, reaper, units"
install -m 644 "$SRC/app.py"                       /opt/sshgate/app.py
install -m 755 "$SRC/sbin/sshgate-open"            /usr/local/sbin/sshgate-open
install -m 755 "$SRC/sbin/sshgate-reap"            /usr/local/sbin/sshgate-reap
install -m 644 "$SRC/systemd/sshgate.service"      /etc/systemd/system/sshgate.service
install -m 644 "$SRC/systemd/sshgate-reap.service" /etc/systemd/system/sshgate-reap.service
install -m 644 "$SRC/systemd/sshgate-reap.timer"   /etc/systemd/system/sshgate-reap.timer

echo "==> sudoers (locked down to the one helper)"
echo 'sshgate ALL=(root) NOPASSWD: /usr/local/sbin/sshgate-open' > /etc/sudoers.d/sshgate
chmod 440 /etc/sudoers.d/sshgate
visudo -cf /etc/sudoers.d/sshgate >/dev/null

echo "==> config / secrets"
if [[ ! -f /etc/sshgate/config.json ]]; then
  "$PY" - "$SRC/config.example.json" <<'PY'
import base64, json, os, secrets, sys
cfg = json.load(open(sys.argv[1])); cfg.pop("_comment", None)
cfg["url_secret"]  = secrets.token_urlsafe(32)
cfg["totp_secret"] = base64.b32encode(os.urandom(20)).decode().rstrip("=")
json.dump(cfg, open("/etc/sshgate/config.json", "w"), indent=2)
PY
  chown sshgate:sshgate /etc/sshgate/config.json
  chmod 640 /etc/sshgate/config.json
  echo "    generated fresh secrets"
else
  echo "    keeping existing /etc/sshgate/config.json"
fi

echo "==> enable services"
systemctl daemon-reload
systemctl enable --now sshgate.service       >/dev/null
systemctl enable --now sshgate-reap.timer    >/dev/null

US="$("$PY" -c "import json;print(json.load(open('/etc/sshgate/config.json'))['url_secret'])")"
TS="$("$PY" -c "import json;print(json.load(open('/etc/sshgate/config.json'))['totp_secret'])")"

cat <<EOF

==================== sshgate installed ====================
Secret link : https://${DOMAIN}/${US}/
Enroll TOTP : otpauth://totp/sshgate:${DOMAIN}?secret=${TS}&issuer=sshgate&period=30&digits=6&algorithm=SHA1
              (or type the key manually: ${TS})

Paste into your HTTPS server block, then reload nginx:

  location /${US}/ {
      access_log off;
      proxy_pass http://127.0.0.1:8787/;
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-Client \$remote_addr;
  }

  nginx -t && systemctl reload nginx

Open the link, enter the code, SSH in. Keep a console/IPMI path as break-glass.
===========================================================
EOF
