#!/bin/bash
# Run locally on VPN VM as root; never restarts WireGuard or sshd.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[ "$(id -u)" = 0 ] || { echo 'Run with sudo'; exit 1; }
[ -x /usr/bin/python3 ] && [ -x /usr/bin/wg ] && [ -x /usr/sbin/ip ]
id avantime-wg >/dev/null
[ "$(getent passwd avantime-wg | cut -d: -f6)" = /var/lib/avantime-wg ]
[ "$(getent passwd avantime-wg | cut -d: -f7)" = /bin/sh ]
[ "$(stat -c %u /var/lib/avantime-wg)" = 0 ]
[ "$(stat -c %u /var/lib/avantime-wg/.ssh)" = 0 ]
[ ! -L /etc/wireguard/wg0.conf ]
[ ! -L /var/lib/avantime-wg-state ]
# Validate syntax before installing any executable or granting sudo.
/usr/bin/python3 -I -c 'import ast; ast.parse(open("helper.py").read())'
install -d -o root -g root -m 700 /var/lib/avantime-wg-state
if [ ! -f /var/lib/avantime-wg-state/wg0.conf.before-install ]; then
  install -o root -g root -m 600 /etc/wireguard/wg0.conf /var/lib/avantime-wg-state/wg0.conf.before-install
fi
if [ ! -f /var/lib/avantime-wg-state/authorized_keys.before-install ]; then
  install -o root -g root -m 600 /var/lib/avantime-wg/.ssh/authorized_keys /var/lib/avantime-wg-state/authorized_keys.before-install
fi
install -o root -g root -m 755 helper.py /usr/local/sbin/avantime-wg-helper
# Read-only preflight: confirms interface/config can be parsed. Prints no keys/config.
printf '%s\n' '{"action":"status"}' | /usr/local/sbin/avantime-wg-helper |
 /usr/bin/python3 -I -c 'import json,sys; r=json.load(sys.stdin); assert r.get("ok"), r; print("WireGuard preflight OK")'
tmp=$(mktemp /etc/sudoers.d/avantime-wg.XXXXXX)
trap 'rm -f "$tmp"' EXIT
printf '%s\n' 'avantime-wg ALL=(root) NOPASSWD: /usr/local/sbin/avantime-wg-helper ""' > "$tmp"
chmod 440 "$tmp"
visudo -cf "$tmp"
mv "$tmp" /etc/sudoers.d/avantime-wg
# Preserve the already verified public key; reject any unexpected authorized keys.
/usr/bin/python3 -I - <<'PY'
from pathlib import Path
import os
p = Path('/var/lib/avantime-wg/.ssh/authorized_keys')
line = p.read_text().strip()
expected = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFg8tsiKetkf45FUChkvEJ+uyL2RcPXr7RyEljQM4Z8N avantime-connect-wg'
if line not in ('restrict,command="/usr/bin/echo WG_ACCESS_OK" ' + expected,
                'restrict,command="/usr/bin/sudo -n /usr/local/sbin/avantime-wg-helper" ' + expected):
    raise SystemExit('Unexpected authorized_keys: review manually; key was not changed')
tmp = p.with_name('authorized_keys.new')
tmp.write_text('restrict,command="/usr/bin/sudo -n /usr/local/sbin/avantime-wg-helper" ' + expected + '\n')
os.chmod(tmp, 0o644)
os.replace(tmp, p)
PY
printf '%s\n' 'Installed. Existing peers unchanged; WireGuard/SSH were not restarted.'
