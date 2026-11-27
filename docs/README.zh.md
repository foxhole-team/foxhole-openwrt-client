<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

为 OpenWrt 路由器提供 VPN 配置、路由规则和简洁的管理面板。
出站 VPN 连接使用 [FoxHole Core](https://github.com/foxhole-team/foxhole-core)。
精简安装为每个选定协议使用独立客户端模块。v1.0.8新增可选且经过独立验证的入站 Hysteria2 服务器包。远程访问需要固定公网 WAN 地址和外部可达的 UDP 端口。

</div>

<p align="center">
    <img
      src="../media/fhg.gif"
      alt="FoxHole OpenWrt"
      width="180"
      height="180"
    >
</p>

<div align="center">

[🇬🇧 English](../README.md) · [🇷🇺 Русский](README.ru.md) · [🇩🇪 Deutsch](README.de.md) · [🇫🇷 Français](README.fr.md) · [🇪🇸 Español](README.es.md) · [🇯🇵 日本語](README.ja.md) · [🇨🇳 **简体中文**](README.zh.md) · [🇸🇦 العربية](README.ar.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<a id="ecosystem"></a>
<a id="-foxhole生态系统"></a>

<div align="center">
  <strong>FoxHole ecosystem</strong><br>
  <a href="https://github.com/foxhole-team/foxhole-guard">FoxHole Guard</a> ·
  <a href="https://github.com/foxhole-team/foxhole-vpn">FoxHole VPN</a> ·
  <a href="https://github.com/foxhole-team/foxhole-core">FoxHole Core</a> ·
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client"><strong>FoxHole OpenWRT</strong></a> ·
  <a href="https://github.com/foxhole-team/foxhole-db">FoxHole DB</a>

<details>
<summary>项目职责</summary>

| 项目 | 用途 |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android：VPN、Tor/I2P、流量规则和本地监控 |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android：简洁VPN客户端及已配对OpenWrt管理 |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | 共用Rust网络核心；功能取决于构建 |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | 路由器VPN及局域网管理 |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | 签名规则和参考数据 |

</details>

</div>

<p align="center"><a href="#quickstart">开始使用</a> · <a href="#features">功能</a> · <a href="#details">详情</a> · <a href="#whats-new">更新内容</a></p>

<a id="whats-new"></a>

> **🆕 更新内容 - 1.0.13 Beta (FLASH r1 · RAM r2)**
>
> - 使用 Bash 安装程序从 macOS、Linux 或 Windows 通过 SSH 安装。全新安装完成设置后会启用软件包自动更新，也可关闭。
> - 软件包更新会检查路由器 API，检查失败时尝试恢复旧版本。修复了家庭 VPN 服务器管理和首个客户端的创建。
> - 可在 LuCI 中导入受支持的 Hysteria 2、VLESS 和 WireGuard 订阅，也可从 Guard 或 VPN 转入。路由器会自动刷新受支持的订阅。
> - 「游戏不走 VPN」使用设置中的标准开关。从「添加」打开路由，展开和折叠箭头的转角清晰可见。
> - 日志使用新的刷新图标，在 RAM 中显示最近十条 VPN 事件。软件状态会显示单独安装的 Hysteria 2。

<a id="quickstart"></a>

## 📦 安装

此客户端连接您自己的VPN服务器或服务商，不附带现成VPN服务器或其访问权限。

选择已发布且经过验证的版本。将`RELEASE_TAG`替换为其标签，`MANIFEST_SHA256`替换为可信`SHA256SUMS`的SHA-256，`INSTALLER_SHA256`替换为同一版本`install.sh`的SHA-256。请通过独立途径确认这些值的真实性。执行前会验证安装器。

### 从电脑安装

在路由器局域网内的电脑上打开已验证的发布版源代码。安装程序使用 Bash 和 OpenSSH。Windows 请使用 Git for Windows。

**macOS / Linux / Git Bash**

```sh
bash tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

**Windows PowerShell**

```powershell
& "$env:ProgramFiles\Git\bin\bash.exe" ./tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

也可以从同一发布版下载 `foxhole-openwrt-install.sh`，用签名校验和核对 SHA-256 后，省略命令中的 `tools/`。PowerShell 示例使用 Git for Windows 的默认安装路径。

安装程序使用默认 IPv4 网关。要选择局域网中的其他路由器，请添加 `--host ROUTER_IP`。按提示核对 SSH 主机密钥，登录并在路由器上阅读许可协议。

### 从路由器终端安装

在路由器上以 root 身份运行命令。

```sh
( set -eu; release_tag='RELEASE_TAG'; manifest_sha256='MANIFEST_SHA256'; installer_sha256='INSTALLER_SHA256'; url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"; installer=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$installer"' EXIT; uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"; printf '%s  %s\n' "$installer_sha256" "$installer" | sha256sum -c -; sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_sha256" --apply )
```

使用 `--apply` 时，交互式安装程序会显示协议并询问 `[y/N]`，默认为“否”。可用 `sh install.sh --license` 阅读协议。非交互式安装须在明确接受后提供 `--accept-license`。手机设置向导中，独立的同意选项默认不勾选。

精简目录默认**仅安装 Hysteria2 客户端**，并存储于闪存。
使用已验证的本地发布包时，可以选择一个协议或组合使用选项：

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` 是 `--wg` 的别名。其他可识别选项包括 `--vmess`、`--tuic`、
`--trojan`、`--shadowsocks`、`--naive`、`--anytls`、`--shadowtls`、`--socks`、`--http`。
每个模块都必须针对您的固件和目标平台发布。在精简目录中，`--all`选择为目标平台发布的全部客户端协议，所选模块必须支持同一种存储模式。明确指定但缺少模块的协议会被拒绝。旧版schema 1需要完全匹配的构建变体，其中`--all`表示所有可识别协议。

| 存储方式 | 行为 |
| --- | --- |
| `--flash` | 重启后引擎仍保留在闪存中。默认选项。 |
| `--ram` | 引擎二进制文件加载到RAM中，重启后按需重新获取。设置保留在闪存中。 |
| `--auto` | 完整资源预算充足时选择闪存，否则选择可用的 RAM 模块组合。 |

`--ram`存储模式与实验性的native RAM bootstrap不同。持久bootstrap注册仍被禁用，冷启动恢复尚未通过验证，自定义ELF库路径的准入问题仍未解决。参见[RAM bootstrap限制](RAM-BOOTSTRAP.md)。

去掉`--apply`即可只检查选定包而不安装。不会为了适配不兼容的包而升级内核软件包。精简目录中的`--server`仅在所选目录包含兼容且经过验证的入站Hysteria服务器包时可用，此时才将其计入资源预算。配置远程访问前保持关闭。

<a id="features"></a>

## 🔌 支持的 VPN 协议

当前可用于路由器的 FoxHole VPN 模块：

| 协议 | 安装选项 | 说明 |
| --- | --- | --- |
| VLESS | `--vless` | 使用VPN配置中给定的参数，通过客户端模块连接兼容的VLESS代理服务器。 |
| Hysteria2 | `--hy2` | 通过QUIC/UDP连接Hysteria2服务器，使用该协议独立的客户端模块。 |
| WireGuard | `--wg` | 与WireGuard对等节点建立L3 IP隧道，由配置提供密钥、地址及网络参数。 |

## 📋 要求

- 带apk包管理器的OpenWrt 25.12.5 或 25.12.6和root权限。直接下载需要路由器联网；本地`--bundle`只需可信局域网。
- 适用于准确固件、目标、架构及所选协议的已发布软件包。当前软件包与更新策略允许 `x86/64` 和 `mediatek/filogic`；SDK 构建或 ARM 架构名称本身不能证明所有路由器型号均兼容。
- 足以容纳完整且经过验证的软件包预算的闪存和 RAM。更改软件包前，安装程序会检查依赖关系、内核 ABI 和暂存空间。
- 从可信本地网络访问。通过Android查找和初次设置时，请将手机连接到路由器Wi-Fi。

[v1.0.6版本](https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/v1.0.6)包含BASE 1.0.6-r1和FoxHole Core 1.0.4客户端模块。兼容的Core更新可以单独安装。软件包的可用性和兼容性取决于所选版本、固件和目标平台。

仅有源码支持和交叉编译的二进制文件，并不能证明路由器兼容性。
只能安装已验证真实性的发布目录中包含的软件包。
入站服务器在未使用的 S2/OpenPGP 软件包中仍有两项经过审查的依赖问题；
针对确切构建的检查及例外的到期时间见[发布说明](RELEASE.md)。

## 支持的路由器

| 型号 | RAM | Flash | OpenWrt | 软件包安装位置 |
|---|---|---|---|---|
| [Cudy WR3000 v1](https://www.cudy.com/products/wr3000-1-0) | 256 MB | 16 MB NOR | 25.12.5 | 仅 RAM |
| [Cudy WR3000S v1](https://www.cudy.com/products/wr3000s-1-0) | 256 MB | 128 MB NAND | 25.12.6 | FLASH |

表中列出的是硬件总容量。安装前，安装程序会检查具体型号及可用空间。

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 使用与配对

更改 PIN 会重置配对：手机需要重新连接，但 VPN 配置和设置会保留。

打开 **LuCI → Services → FoxHole OpenWRT Client → Panel**，设置 PIN 并添加 VPN 配置。
规则可将设备、域名和国家/地区流量通过 VPN 或直接连接发送。

`ACCESS_LOCAL_NETWORK` - 用于发现、设置和管理路由器。在 Android 17（API 37）及更高版本上，若应用的目标 API 也是 37 或更高版本，会在 LAN 操作前请求系统权限。拒绝后会阻止这些操作。

手机设置会在当前连接 Wi-Fi 的私有 IPv4 网关地址查找路由器；也可手动输入地址。
配对前，手机会验证 SSH 身份及路由器的私有 LAN TLS 身份。
已有 PIN 保持不变。管理地址仍为私有地址。
解除配对会移除管理权限。若要撤销远程客户端的 VPN 凭据，请另行删除该客户端。
删除旧的共享配置只会移除其记录，无法撤销外部 VPN 服务商持有的凭据。

创建远程VPN客户端需要单独验证的入站Hysteria服务器包，只有所选发布目录包含该包时才可用`--server`安装。此外还需公网WAN地址和外部可达的UDP端口。满足条件后，**创建 VPN 配置**可添加远程客户端；选择已有客户端会打开其配置。

家庭网络中的 VPN 自动切换在实际路由验收完成前保持禁用，
验收包括故障时阻断流量（fail-closed）和隧道所有权检查。

在 Android 应用中：

Wi-Fi 图标仅表示实际的 Wi-Fi 连接，不读取 SSID 或访问定位。搜索和新的设置/配对需要 Wi-Fi。手动地址会在可用时一次性填入当前 Wi-Fi 的私有 IPv4 网关，之后仍可编辑。

通过家庭 VPN 管理是独立选项，每个已有配对默认关闭。还需要您确认“公网 IP 地址”（路由器有公网 IP 和入站 VPN 服务），并具备可用的活动 VPN 路由。此确认不会分配地址或配置防火墙。应用可通过该 VPN 网络，使用已有的固定 TLS 身份和配对认证，尝试管理已保存的私有地址；不会开放 WAN 管理端口，也不会通过移动网络进行新的搜索或配对。

只有已配对且经过认证的路由器直接发送到应用的入站 VPN 配置，才带有独立的应用关联元数据。连接 URI、配置和 QR 格式均不改变。通用网页/QR/服务商导出仍不带标记；导入的提示本身不能建立信任。

自动识别还要求已保存的本地配置、当前配置内容及所选配对相匹配，且该配置确实通过应用自身的 VPN 连接。每次实际连接只进行一次有时间限制的检查，没有定时器、自动重试或服务商配置轮询。“重试配对”是明确的 Wi-Fi/权限/PIN 流程：认证成功前保留原有记录，绝不自动接受已改变的证书身份。

## 限制

- 国家规则使用IP范围，域名规则依赖路由器DNS，不识别网站所有者的国家，也不分析HTTPS内容。
- 活动Core连接意外断开会阻止其VPN路由。单独的Kill switch设置控制没有活动配置时的阻止，默认关闭。
- 规则优先级、本地地址例外和入站服务器限制见[架构](ARCHITECTURE.md)。

## 🧩 稍后添加协议

在**路由器 VPN → 协议**中选择可用协议并确认安装。
已配对的 Android 应用也提供相同操作。
每个协议使用独立、精简且已签名的引擎软件包；
不会悄悄替换成更大的通用引擎。

添加尚未使用的协议不会中断当前 VPN。
更新正在使用的协议时会请求重新连接。删除协议前，请先停止使用该协议。
只会提供针对您路由器确切目标平台发布的软件包。

## ♻️ 更新与移除

### 📥 FoxHole 软件包更新

在网页面板或已配对应用的 **设置 → FoxHole 更新** 中，通过同一套经过身份验证的事务检查并安装更新。更新范围是 FoxHole 面板/runtime 和所选的已安装客户端协议模块，并保留其 FLASH/RAM 模式。新协议须单独安装。配置与配对会保留，不升级 OpenWrt 固件或其他系统软件包。

新安装的软件包会在所有者设置 PIN 后开启自动更新。若要关闭，可在设置时取消勾选，或向安装程序传入 `--no-auto-update`。重新配对会保留原有选择。稍后也可在设置中更改。

启用后，路由器每天检查并安装经过验证的 FoxHole 软件包更新。取消手机配对不会关闭此策略。没有更新器的旧软件包须先进行单独审核的迁移。请参阅[软件更新](UPDATES.md)。

通过已配对路由器或手机上的**路由器 VPN → 协议**添加或更新协议。
精简安装器仅用于初始设置。它会保留私有恢复备份，并检查 DHCP 设置未发生变化。
在路由仍处于活动状态时，删除软件包前请先按照[回滚/移除说明](ROLLBACK.md)操作。
请使用经过验证的发布软件包。
不使用旧版安装器和ARM专用下载。FoxHole Core支持Hysteria2。现有legacy配置继续使用独立的Hysteria运行时，不会自动迁移到Core。更新前请手动停止正在运行的legacy Hysteria连接。

- **使用说明:** [CLI](CLI.md) · [Updates](UPDATES.md) · [Rollback](ROLLBACK.md)
- **架构:** [Architecture](ARCHITECTURE.md) · [Mobile networks](MOBILE-NETWORKS.md) · [Backup](BACKUP-ARCHITECTURE.md) · [Profile origin](PROFILE-ORIGIN.md)
- **维护:** [Release](RELEASE.md) · [Bundle transport](BUNDLE-TRANSPORT.md) · [RAM install](RAM-INSTALL.md) · [Bootstrap](RAM-BOOTSTRAP.md) · [Prerequisites](RAM-PREREQUISITES.md) · [RAM updates](RAM-UPDATE-CONTROLLER.md) · [Engine origin](engine-release-origin.md) · [Security](../SECURITY.md)

### 卸载 FoxHole

在 LuCI 中打开 **服务 → FoxHole OpenWRT Client → Uninstall FoxHole**，确认要卸载的安装。在路由器的 root 终端运行以下命令。

```sh
/usr/libexec/foxhole-uninstall
```

命令会显示计划并要求确认。卸载 FLASH 版会断开 VPN 并移除基础软件包。对于托管 RAM 安装，请在禁用自动启动后重启 OpenWrt。如果重启后仍有 FLASH 副本，请单独卸载。网络设置、配置文件和配对设备将保留。FLASH 中已有的恢复缓存将保留。

## 🤝 参与开发

请通过[Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues)报告错误或提出修改建议。

## 💖 支持开发

我们完全利用自己的时间和资源开发和维护FoxHole OpenWrt，并在开发中使用AI工具。您的支持能让我们为项目投入更多时间，加快开发进度。

<a id="cryptocurrency-wallets"></a>

### 🪙 加密货币钱包

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

## 📄 许可证

[许可证](../LICENSE) · [第三方组件许可证](../THIRD_PARTY_NOTICES.md)
