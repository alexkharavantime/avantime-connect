#!/bin/bash
# Run on vpn-dev as root AFTER installing the updated helper. No VPN restart.
set -euo pipefail
cd -- "$(dirname -- "$0")"
[ "$(id -u)" = 0 ] || { echo 'Run with sudo'; exit 1; }
[ -x /usr/sbin/nft ]
[ -f /var/lib/avantime-wg-state/managed.json ]
[ ! -L /var/lib/avantime-wg-state ]
systemctl is-active --quiet wg-quick@wg0.service
# Enabling makes currently managed peers PROD-only until explicit DEV grants.
# Original unmanaged peers and the existing NAT table remain untouched.
install -o root -g root -m 644 avantime-access.service /etc/systemd/system/avantime-access.service
install -d -o root -g root -m 755 /etc/systemd/system/wg-quick@wg0.service.d
printf '[Unit]\nRequires=avantime-access.service\nAfter=avantime-access.service\n' > /etc/systemd/system/wg-quick@wg0.service.d/avantime-access.conf
install -o root -g root -m 600 /dev/null /var/lib/avantime-wg-state/access-enabled
systemctl daemon-reload
systemctl enable avantime-access.service
# Reapply also when the unit was already active. Never clears rules on stop.
/usr/local/sbin/avantime-wg-helper --restore-access
systemctl start avantime-access.service
printf '%s\n' 'Access control enabled; managed peers default to PROD. VPN was not restarted.'
