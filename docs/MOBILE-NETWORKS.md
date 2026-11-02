# Mobile management networks

The mobile HTTPS API listens on port 8443 at private IPv4 addresses of approved
local devices. An absent `foxhole.panel.mobile_devices` UCI list selects only
the active primary `lan` device. An explicit list selects one to eight distinct
device names. It does not change the separate `lan_devices` VPN routing policy.
WAN, loopback and devices reporting default routes are refused. At most sixteen
interface/address tuples are accepted. Socket addresses are unique even when
approved devices have overlapping local addresses; firewall tuples retain their
device binding. Pairing tokens, peer IP, MAC and TLS identity checks are unchanged.

The helper prepares a root-owned endpoint set in
`/etc/nftables.d/30-foxhole-mobile.nft`. A static fw4 input rule accepts only these
device/address tuples. An earlier private table drops port 8443 on every other
tuple and drops IPv6. Both runtime policies pass native nft preflight before
publication. The persistent set is a narrow mutable BASE conffile: update
verification checks root ownership, regular-file type, single link, protected
parents, size and canonical endpoint-set contents. Other NFT payloads retain
their existing verification rules.

Stopping clears the allowlist and retains an empty drop-all policy while
`rc.common` subsequently kills the listener. If clearing fails, a fixed stdin
nft transaction installs the drop-all table; its failure is returned. Neither
path removes the protective table. Uninstall cleanup after independently
confirmed listener termination is pending; an owned deny table may remain
until reboot. Native Ucode, nft, procd and boot/reload behavior require separate
device qualification; source-adapted tests are not that qualification.

Phone provisioning already observes the authenticated CGI peer address and ARP
MAC across local devices. The optional handoff implementation still generates
rules for the primary LAN, and advertises `phoneHandoff: false`. Multi-device
handoff requires separate device-bound lease changes; this policy does not
enable it or rewrite existing phone records.
