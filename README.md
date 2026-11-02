<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

VPN profiles, routing rules and a simple panel for OpenWrt routers.
Uses [FoxHole Core](https://github.com/foxhole-team/foxhole-core) for outgoing VPN
connections. Compact installations use a separate client module for each selected protocol. The incoming Hysteria server is provided separately and is not included in the published v1.0.1 client bundle.

</div>

<p align="center">
    <img
      src="media/fhg.gif"
      alt="FoxHole OpenWrt"
      width="180"
      height="180"
    >
</p>

<div align="center">

[![English](https://img.shields.io/badge/%F0%9F%87%AC%F0%9F%87%A7-English-ff7a00?style=flat-square)](README.md)
[![Русский](https://img.shields.io/badge/%F0%9F%87%B7%F0%9F%87%BA-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-ff7a00?style=flat-square)](docs/README.ru.md)
[![Deutsch](https://img.shields.io/badge/%F0%9F%87%A9%F0%9F%87%AA-Deutsch-ff7a00?style=flat-square)](docs/README.de.md)
[![Français](https://img.shields.io/badge/%F0%9F%87%AB%F0%9F%87%B7-Fran%C3%A7ais-ff7a00?style=flat-square)](docs/README.fr.md)
[![Español](https://img.shields.io/badge/%F0%9F%87%AA%F0%9F%87%B8-Espa%C3%B1ol-ff7a00?style=flat-square)](docs/README.es.md)
[![日本語](https://img.shields.io/badge/%F0%9F%87%AF%F0%9F%87%B5-%E6%97%A5%E6%9C%AC%E8%AA%9E-ff7a00?style=flat-square)](docs/README.ja.md)
[![简体中文](https://img.shields.io/badge/%F0%9F%87%A8%F0%9F%87%B3-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-ff7a00?style=flat-square)](docs/README.zh.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<p align="center"><a href="#quickstart">Get started</a> · <a href="#features">Features</a> · <a href="#details">Details</a> · <a href="#whats-new">What's new</a></p>

<a id="whats-new"></a>

> **🆕 What's new - 1.0.2 Beta**
>
> - Fixed local-network API access and the web interface.
> - Fixed charts and the display of settings.
> - Added backup and restore for settings, VPN profiles and clients.
> - Added a view of paired mobile devices.
> - Increased the PIN to six digits and added lockouts after incorrect attempts. The PIN can be changed through LuCI.
> - Supports pairing with up to 10 mobile devices.
> - Fixed verification of GitHub release metadata.
> - Refined notifications, confirmation dialogs, help and tooltips.

<a id="features"></a>

## 🔌 Supported VPN protocols

Current FoxHole VPN modules for the router:

| Protocol | Installation option | Description |
| --- | --- | --- |
| VLESS | `--vless` | Proxy connection to a compatible VLESS server using the settings supplied by the VPN profile. |
| Hysteria2 | `--hy2` | Connection to a Hysteria2 server over QUIC/UDP, provided by its dedicated client module. |
| WireGuard | `--wg` | Layer-3 IP tunnel to a WireGuard peer; the profile supplies keys, addresses and network settings. |

## 📋 Requirements

- OpenWrt 25.12.5 with the apk package manager and root access. Direct package downloads require router Internet access; a local `--bundle` only needs trusted LAN access.
- Released packages matching the exact firmware, target, architecture and selected protocols. The current package/update policy admits `x86/64` and `mediatek/filogic`; an SDK build or ARM architecture name does not qualify every router model.
- Enough flash and RAM for the complete verified package budget. The installer checks dependencies, kernel ABI and staging space before changing packages.
- Access from a trusted local network. For discovery and initial setup from Android, connect the phone to the router’s Wi-Fi.

In this public beta, outgoing VPN modules use FoxHole Core 1.0.2. Source
support and a cross-compiled binary alone do not establish router compatibility.
Only packages included in an authenticated release catalog can be installed.
The incoming server has two reviewed dependency findings in unused S2/OpenPGP
packages; exact-build checks and expiry are documented in [Release](docs/RELEASE.md).

<a id="quickstart"></a>

## 📦 Install

This client connects to your own VPN server or provider. Ready-made VPN servers and access to them are not included.

Choose a published, verified release. Replace `RELEASE_TAG` with its tag, `MANIFEST_SHA256` with the trusted SHA-256 of its `SHA256SUMS`, and `INSTALLER_SHA256` with the SHA-256 of that release’s `install.sh`. Authenticate these values independently. The installer is checked before execution:

```sh
(
  set -eu
  release_tag='RELEASE_TAG'
  manifest_sha256='MANIFEST_SHA256'
  installer_sha256='INSTALLER_SHA256'
  url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"
  installer=$(mktemp /tmp/foxhole-install.XXXXXX)
  trap 'rm -f "$installer"' EXIT
  uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"
  printf '%s  %s\n' "$installer_sha256" "$installer" | sha256sum -c -
  sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_sha256" --apply
)
```

With `--apply`, an interactive installer displays the agreement and asks `[y/N]`, defaulting to No. Read it with `sh install.sh --license`. Noninteractive installation requires `--accept-license` after explicit acceptance. In the phone setup wizard, the separate agreement choice starts unchecked.

For compact catalogs, the default is the **Hysteria2 client only**, stored in
flash. With a verified local release bundle, choose one protocol or combine flags:

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` is an alias for `--wg`. Other recognized flags: `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Each module must be published for your firmware and target. In a compact catalog, `--all` selects all client protocols available for that target; they must share a supported storage mode. An explicitly requested protocol is rejected if its module is unavailable. Legacy schema 1 catalogs require an exact build variant; there, `--all` means all recognized protocols.

| Storage | Behavior |
| --- | --- |
| `--flash` | Engine stays on flash after reboot. Default. |
| `--ram` | Engine uses RAM and downloads its pinned binary after reboot. Settings stay on flash. |
| `--auto` | Chooses flash when the complete budget fits, otherwise an available RAM module set. |

Remove `--apply` to check the selected bundle without installing it. Kernel
packages are never upgraded to make an incompatible bundle fit. For compact
catalogs, `--server` adds the incoming Hysteria server to the resource budget.
It stays off until remote access is configured.

<p align="center">
  <img src="media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 Use and pair

Changing the PIN resets pairings: you will need to connect the phone again, while VPN profiles and settings are preserved.

Open **LuCI → Services → FoxHole**, choose a PIN and add a VPN profile. Rules
can send devices, domains and country traffic through VPN or directly.

`ACCESS_LOCAL_NETWORK` - router discovery, setup and management. On Android 17 (API 37) or later, when the app targets API 37 or later, the app requests the system permission before LAN actions. Denial blocks those actions.

Phone setup looks for a router at the private IPv4 gateway of the connected Wi-Fi
network; a manual address is available. The
phone verifies SSH identity and the router's private LAN TLS identity before
pairing. An existing PIN is preserved. The management endpoint remains private.
Unpairing removes management access. Delete the remote client separately to
revoke its VPN credentials. Removing a legacy shared profile only removes its
record; it cannot revoke credentials held by an external VPN provider.

The published v1.0.1 client bundle does not include the incoming Hysteria server. Creating remote VPN clients requires a separate verified server package; `--server` is available only when the selected catalog includes it. A public WAN address and an externally reachable UDP port are also required.

Remote access requires the Hysteria server selected with `--server`. On a router
with a public WAN address, **Create VPN profile** adds a remote client. Selecting a client opens
its existing profile.
The UDP listener must also be reachable from outside your home network.
Automatic home-network VPN switching remains disabled until actual routing
acceptance, including fail-closed and ownership checks.

In the Android apps:

The Wi-Fi icon reports only a physical Wi-Fi connection, without an SSID or location access. Search and new setup/pairing require Wi-Fi. Manual entry is prefilled once with the current private IPv4 Wi-Fi gateway when available and stays editable.

Manage through home VPN is a separate opt-in, OFF by default for each existing pairing. It also requires your Public IP address confirmation (the router has a public IP and incoming VPN service) and a usable active VPN route. That confirmation does not assign an address or configure the firewall. The app can attempt foreground control through that VPN network at the saved private endpoint using the existing pinned TLS identity and paired authentication; it opens no WAN management port and does not enable discovery or new pairing over mobile data.

Only incoming-VPN profiles delivered directly to the app by an authenticated paired router receive separate app-link metadata. Their connection URI, configuration and QR formats are unchanged. Generic web/QR/provider exports remain unmarked, and imported hints cannot establish trust.

Automatic recognition additionally requires the matching saved local profile, current configuration and selected pairing, with that profile actually connected through the app-owned VPN. It makes one bounded check per actual connection, with no timer, automatic retry or provider-profile polling. Retry pairing is an explicit Wi-Fi/permission/PIN flow: the old record remains until authentication succeeds, and a changed certificate identity is never accepted silently.

## Limitations

- Country rules use IP ranges, and domain rules depend on router DNS. They do not determine the website owner’s country or inspect HTTPS content.
- Unexpected loss of the active Core connection blocks its VPN routing. The separate Kill switch setting controls blocking without an active profile and is off by default.
- Rule priorities, local-address exceptions and incoming-server limitations are described in the [architecture](docs/ARCHITECTURE.md).

## 🧩 Add a protocol later

In **Router VPN → Protocols**, select an available protocol and confirm its
installation. The same controls are available in the paired Android app.
Each protocol uses a separate compact, signed engine package; there is no
silent replacement with a larger universal engine.

Adding an unused protocol keeps the current VPN running. Updating the active
protocol asks to reconnect. Stop using a protocol before removing it.
Only packages published for your exact router target are offered.

## ♻️ Update and remove

### 📥 FoxHole package updates

Use **Settings → FoxHole update** in the web panel or paired app to check and install updates through the same authenticated transaction. The update covers the FoxHole panel/runtime and selected installed client protocol modules, preserving their FLASH/RAM choices. New protocols are installed separately. Profiles and pairing are preserved; OpenWrt firmware and unrelated system packages are not upgraded.

Direct CLI/backend installations leave automatic updates off by default. During a new phone Setup, the separate visible automatic-update checkbox starts enabled; clear it to opt out. The chosen policy is written after installation and pairing. Pairing an existing router preserves its policy; change it later in Settings.

When enabled, the router checks daily and installs verified FoxHole package updates. Unpairing the phone does not disable this policy. Older packages without the updater need a separately reviewed migration. See [software updates](docs/UPDATES.md).

Add or update protocols through **Router VPN → Protocols** on the paired router
or phone. The compact installer is for initial setup only. It keeps private
recovery backups and checks that DHCP settings remain unchanged.
Use [rollback/removal](docs/ROLLBACK.md) before deleting packages while routing
is active. Use verified release packages. Legacy installers and ARM-only downloads are not used. Hysteria2 is supported by FoxHole Core. Existing legacy profiles continue to use the separate Hysteria runtime and are not migrated to Core automatically. Stop an active legacy Hysteria connection manually before updating.

[Commands](docs/CLI.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Build and release](docs/RELEASE.md) · [Security](SECURITY.md)

<a id="ecosystem"></a>

## 🔗 FoxHole ecosystem

| Project | Role |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, traffic rules and local monitoring |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: simple VPN client and paired OpenWrt management |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | Shared Rust networking core; features depend on the build |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | Router VPN and local-network management |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Signed rules and reference datasets |

## 🤝 Contributing

Report bugs and propose changes through [Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues).

## 💖 Support development

We develop and maintain FoxHole OpenWrt entirely with our own time and resources, using AI tools in development. Your support helps us dedicate more time to the project and speed up development.

<a id="cryptocurrency-wallets"></a>

### 🪙 Cryptocurrency wallets

**XMR (Monero):**

```text
48yBVPTdcyJ1WoJtnKmVpEZziEsDy4HvbCW7eQDS9mfdiWPFXwZ8F5h9YZ2UTTBLxPcJgQgvth7iqLZM2yMCaQ432qaouqr
```

**BTC (Bitcoin):**

```text
bc1qatnyy7jcpqrp0d3dk9rta9vqfejgh4mysd6m2f
```

**ETH (Ethereum):**

```text
0xDEBA357Cc8f5E865ea7FFa98E138C8241A16A465
```

## 📄 Licenses

[License](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
