<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

为 OpenWrt 路由器提供 VPN 配置、路由规则和简洁的管理面板。
出站 VPN 连接使用 [FoxHole Core](https://github.com/foxhole-team/foxhole-core)。
精简安装为每个选定协议使用独立客户端模块。入站Hysteria服务器单独提供，不包含在已发布的v1.0.1客户端套件中。

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

[![English](https://img.shields.io/badge/%F0%9F%87%AC%F0%9F%87%A7-English-ff7a00?style=flat-square)](../README.md)
[![Русский](https://img.shields.io/badge/%F0%9F%87%B7%F0%9F%87%BA-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-ff7a00?style=flat-square)](README.ru.md)
[![Deutsch](https://img.shields.io/badge/%F0%9F%87%A9%F0%9F%87%AA-Deutsch-ff7a00?style=flat-square)](README.de.md)
[![Français](https://img.shields.io/badge/%F0%9F%87%AB%F0%9F%87%B7-Fran%C3%A7ais-ff7a00?style=flat-square)](README.fr.md)
[![Español](https://img.shields.io/badge/%F0%9F%87%AA%F0%9F%87%B8-Espa%C3%B1ol-ff7a00?style=flat-square)](README.es.md)
[![日本語](https://img.shields.io/badge/%F0%9F%87%AF%F0%9F%87%B5-%E6%97%A5%E6%9C%AC%E8%AA%9E-ff7a00?style=flat-square)](README.ja.md)
[![简体中文](https://img.shields.io/badge/%F0%9F%87%A8%F0%9F%87%B3-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-ff7a00?style=flat-square)](README.zh.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<p align="center"><a href="#quickstart">开始使用</a> · <a href="#features">功能</a> · <a href="#details">详情</a> · <a href="#whats-new">更新内容</a></p>

<a id="whats-new"></a>

> **🆕 更新内容 - 1.0.3 Beta**
>
> - 修复本地网络 API 访问和 Web 界面。
> - 修复图表和设置显示。
> - 新增设置、VPN 配置和客户端的备份与恢复。
> - 新增已配对移动设备列表。
> - PIN 增至六位，并在错误尝试后锁定。PIN 可通过 LuCI 更改。
> - 支持最多 10 台移动设备配对。
> - 修复 GitHub 发布数据验证。
> - 改进通知、确认窗口、帮助和提示。
> - 修复准备 RAM 软件包恢复时对系统证书符号链接的验证。
> - 在连接中断诊断中加入 VPN 进程退出码。
> - 修复 OpenWrt 客户端更新所用的 VPN 模块链接。

<a id="features"></a>

## 🔌 支持的 VPN 协议

当前可用于路由器的 FoxHole VPN 模块：

| 协议 | 安装选项 | 说明 |
| --- | --- | --- |
| VLESS | `--vless` | 使用VPN配置中给定的参数，通过客户端模块连接兼容的VLESS代理服务器。 |
| Hysteria2 | `--hy2` | 通过QUIC/UDP连接Hysteria2服务器，使用该协议独立的客户端模块。 |
| WireGuard | `--wg` | 与WireGuard对等节点建立L3 IP隧道，由配置提供密钥、地址及网络参数。 |

## 📋 要求

- 带apk包管理器的OpenWrt 25.12.5和root权限。直接下载需要路由器联网；本地`--bundle`只需可信局域网。
- 适用于准确固件、目标、架构及所选协议的已发布软件包。当前软件包与更新策略允许 `x86/64` 和 `mediatek/filogic`；SDK 构建或 ARM 架构名称本身不能证明所有路由器型号均兼容。
- 足以容纳完整且经过验证的软件包预算的闪存和 RAM。更改软件包前，安装程序会检查依赖关系、内核 ABI 和暂存空间。
- 从可信本地网络访问。通过Android查找和初次设置时，请将手机连接到路由器Wi-Fi。

此公开测试版的出站 VPN 模块使用 FoxHole Core 1.0.2。
仅有源码支持和交叉编译的二进制文件，并不能证明路由器兼容性。
只能安装已验证真实性的发布目录中包含的软件包。
入站服务器在未使用的 S2/OpenPGP 软件包中仍有两项经过审查的依赖问题；
针对确切构建的检查及例外的到期时间见[发布说明](RELEASE.md)。

<a id="quickstart"></a>

## 📦 安装

此客户端连接您自己的VPN服务器或服务商，不附带现成VPN服务器或其访问权限。

选择已发布且经过验证的版本。将`RELEASE_TAG`替换为其标签，`MANIFEST_SHA256`替换为可信`SHA256SUMS`的SHA-256，`INSTALLER_SHA256`替换为同一版本`install.sh`的SHA-256。请通过独立途径确认这些值的真实性。执行前会验证安装器：

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
| `--ram` | 引擎使用 RAM，并在重启后下载其固定版本的二进制文件。设置保留在闪存中。 |
| `--auto` | 完整资源预算充足时选择闪存，否则选择可用的 RAM 模块组合。 |

移除 `--apply` 可仅检查选定发布包，而不执行安装。
绝不会通过升级内核软件包来适配不兼容的发布包。
对于精简目录，`--server` 会将入站 Hysteria 服务器计入资源预算。
在配置远程访问之前，服务器保持关闭。

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 使用与配对

更改 PIN 会重置配对：手机需要重新连接，但 VPN 配置和设置会保留。

打开 **LuCI → Services → FoxHole**，设置 PIN 并添加 VPN 配置。
规则可将设备、域名和国家/地区流量通过 VPN 或直接连接发送。

`ACCESS_LOCAL_NETWORK` - 用于发现、设置和管理路由器。在 Android 17（API 37）及更高版本上，若应用的目标 API 也是 37 或更高版本，会在 LAN 操作前请求系统权限。拒绝后会阻止这些操作。

手机设置会在当前连接 Wi-Fi 的私有 IPv4 网关地址查找路由器；也可手动输入地址。
配对前，手机会验证 SSH 身份及路由器的私有 LAN TLS 身份。
已有 PIN 保持不变。管理地址仍为私有地址。
解除配对会移除管理权限。若要撤销远程客户端的 VPN 凭据，请另行删除该客户端。
删除旧的共享配置只会移除其记录，无法撤销外部 VPN 服务商持有的凭据。

已发布的v1.0.1客户端套件不包含入站Hysteria服务器。创建远程VPN客户端需要单独验证的服务器包，只有包含该包的目录才可使用`--server`。还需要公网WAN地址和可从外部访问的UDP端口。

远程访问需要通过 `--server` 选中的 Hysteria 服务器。
在具有公网 WAN 地址的路由器上，**创建 VPN 配置**会添加一个远程客户端。
选择客户端会打开其已有配置。
UDP 监听端口还必须能够从家庭网络外部访问。
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

通过 CLI/backend 直接安装时，自动更新默认关闭。通过手机进行新设置时，独立且可见的自动更新复选框默认开启；不希望启用时可取消勾选。所选策略在安装和配对后写入。配对已有路由器会保留原有策略，稍后可在设置中更改。

启用后，路由器每天检查并安装经过验证的 FoxHole 软件包更新。取消手机配对不会关闭此策略。没有更新器的旧软件包须先进行单独审核的迁移。请参阅[软件更新](UPDATES.md)。

通过已配对路由器或手机上的**路由器 VPN → 协议**添加或更新协议。
精简安装器仅用于初始设置。它会保留私有恢复备份，并检查 DHCP 设置未发生变化。
在路由仍处于活动状态时，删除软件包前请先按照[回滚/移除说明](ROLLBACK.md)操作。
请使用经过验证的发布软件包。
不使用旧版安装器和ARM专用下载。FoxHole Core支持Hysteria2。现有legacy配置继续使用独立的Hysteria运行时，不会自动迁移到Core。更新前请手动停止正在运行的legacy Hysteria连接。

[命令](CLI.md) · [架构](ARCHITECTURE.md) ·
[构建与发布](RELEASE.md) · [安全](../SECURITY.md)

<a id="ecosystem"></a>

## 🔗 FoxHole生态系统

| 项目 | 用途 |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android：VPN、Tor/I2P、流量规则和本地监控 |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android：简洁VPN客户端及已配对OpenWrt管理 |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | 共用Rust网络核心；功能取决于构建 |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | 路由器VPN及局域网管理 |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | 签名规则和参考数据 |

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
