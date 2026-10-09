# DEV / PROD access (0.4.2)

This release is gated off by default (`access_control_enabled=false`). Installing
only the Windows package does not grant DEV access. Existing registrations and
PROD profiles remain usable. Never copy a user's private key to the backend.

## Policy

- DEV permits forwarding to WIN-APP-DEV `10.20.0.20/32`, plus DNS queries
  to `10.40.0.10` on TCP/UDP port 53 only. Its profile adds `10.40.0.10/32`;
  this does not grant access to other PROD services or a default route.
- PROD preserves the existing permitted work network `10.40.0.0/24`, with the
  desktop button fixed to `10.40.0.20`.
- Each user can have DEV, PROD or both. Revocation still disables the whole device.
- Windows routes and buttons follow the profile. The VPN server independently
  enforces the grant, including traffic from a manually modified client profile.
- Only journal-owned peers are restricted. Existing unmanaged peers/site tunnels
  remain outside this policy. This is not a claim that all access to PROD is
  VPN-only: computers inside the office may have a separate Ethernet route.
- No nft ruleset flush, NAT replacement, WireGuard restart, or key rotation.

## Deployment order

1. Complete both CI workflows for the exact release commit. Back up the backend
   database/configuration and root-only WireGuard journal/config using the existing
   operational backup process. Do not print private keys or `.env` contents.
2. On `vpn-dev` (`10.20.0.2`), install this commit's helper using the existing
   `install-server.sh` procedure. Preserve its dedicated SSH account/forced command.
   Confirm nftables is installed and the existing interface is `wg0`.
3. From `deploy/wireguard`, run `sudo bash enable-access.sh`. This installs a
   startup dependency and atomically applies the dedicated `inet avantime_access`
   chain. Existing managed peers initially retain PROD; unmanaged peers and the
   original NAT table are unchanged. Failure must be investigated before proceeding.
4. Deploy the matching backend/UI commit using the existing Compose configuration
   and persistent Mongo volume. Set `access_control_enabled=true` in the backend
   environment only after step 3 succeeds. The `admin-backend/compose.access.yml`
   overlay supplies this flag; keep the same Compose project name and existing
   configuration files/volumes. Do not use `docker compose down -v`.
   Exact deployment commands depend on the live checkout/Compose overlays; inspect
   these before changing the running release.
5. In the admin UI, find the selected accounts and verify their registered devices
   and assigned VPN addresses. Select **DEV и PROD**.
   Wait for an applied confirmation; a saved assignment alone is not success.
   Use **Повторить применение** after fixing a reported application failure.
6. Upgrade each client under its existing Windows account. Disconnect its VPN,
   press **Обновить доступ**, reconnect and check the recent handshake. The same
   key, VPN address and owned encrypted tunnel are retained. New invitations are
   unnecessary. Only the routes and available desktop buttons change.
7. Check both desktop destinations. Check a PROD-only account cannot connect to
   `10.20.0.20:3389` through its VPN even if a route is added manually. On the client's
   external network, disconnect and verify both private destinations are unavailable.

Do not remove the startup dependency or downgrade the helper after enabling access
without a reviewed rollback: the server must continue enforcing the latest grants.
If the API is rolled back, keep the helper, journal and nft rules in place; do not
interpret a legacy client's visible button as an authorization decision.

## Recovery and credentials

Original enrollment snapshots remain immutable for retry/recovery. The separate
`POST /api/enroll/profile` reads the current effective access, using the already
DPAPI-protected consumed invitation plus the exact public key and device name.
The invitation remains single-use for enrollment, but is retained as a read-only
credential for that device's profile. No private key is sent, and the token never
appears in the URL. Inactive/revoked devices are denied. Protect and redact request
bodies in any proxy diagnostics. Access changes require the admin bearer token.

The helper persists monotonically increasing per-user policy revisions and binds
owned peers to those groups. A delayed enrollment cannot restore an older grant.
API publication waits for helper confirmation; a failed application returns an
error and remains retryable. Restore failure exits nonzero and prevents wg-quick
starting through the installed systemd dependency. External firewall managers must
not flush this table after startup; reapply `avantime-access` rules after such an
administrative change before allowing new VPN sessions.

## Split DNS upgrade (0.4.2)

Upgrade Windows clients to 0.4.2 before publishing/refreshing the new DEV-only
profile: older 0.4.0/0.4.1 clients validate the original single-host DEV route and
reject the new DNS host route. PROD and DEV+PROD route strings are unchanged.
The 0.4.2 client also supports existing saved DEV profiles and adds the effective
DNS host route locally; no new invitation, key, VPN IP or assignment is required.

On the VPN VM deploy the updated helper and reapply its access chain using
`enable-access.sh` (or restart only `avantime-access.service` after replacing the
helper). Without this step DEV-only clients cannot reach DNS, even with the client
route installed. Preserve existing SSH authorized keys and the NAT table. The DNS
exception applies only to active/pending-add managed peers; revoked peers are
still denied, including DNS. PROD behavior remains unchanged.

Then deploy the backend so new enrollment/current-profile responses contain the
DEV-only DNS route. Original enrollment recovery snapshots remain immutable.
Validate system name resolution for `WIN-APP-PROD.AD.AVANTIME.LV` without an explicit
DNS server, UDP and TCP DNS, and deny DEV-only traffic to `10.40.0.10:3389` and
`10.40.0.20:3389`. DNS name visibility does not grant RDP permission to PROD.
