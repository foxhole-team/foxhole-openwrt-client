<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

OpenWrt ルーター向けの VPN プロファイル、ルーティングルール、シンプルな管理パネル。
外向きの VPN 接続には [FoxHole Core](https://github.com/foxhole-team/foxhole-core) を使用します。
コンパクト構成では選択プロトコルごとに個別のクライアントモジュールを使います。v1.0.8では、検証済みの着信用Hysteria2サーバーパッケージを任意で追加できます。リモートアクセスには固定のパブリックWANアドレスと外部から到達可能なUDPポートが必要です。

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

[🇬🇧 English](../README.md) · [🇷🇺 Русский](README.ru.md) · [🇩🇪 Deutsch](README.de.md) · [🇫🇷 Français](README.fr.md) · [🇪🇸 Español](README.es.md) · [🇯🇵 **日本語**](README.ja.md) · [🇨🇳 简体中文](README.zh.md) · [🇸🇦 العربية](README.ar.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<a id="ecosystem"></a>
<a id="-foxholeエコシステム"></a>

<div align="center">
  <strong>FoxHole ecosystem</strong><br>
  <a href="https://github.com/foxhole-team/foxhole-guard">FoxHole Guard</a> ·
  <a href="https://github.com/foxhole-team/foxhole-vpn">FoxHole VPN</a> ·
  <a href="https://github.com/foxhole-team/foxhole-core">FoxHole Core</a> ·
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client"><strong>FoxHole OpenWRT</strong></a> ·
  <a href="https://github.com/foxhole-team/foxhole-db">FoxHole DB</a>

<details>
<summary>各プロジェクトの役割</summary>

| プロジェクト | 役割 |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android：VPN、Tor/I2P、通信ルールとローカル監視 |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android：シンプルなVPNとペアリング済みOpenWrt管理 |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | 共通Rustネットワークコア。機能はビルドによる |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | ルーターVPNとローカルネットワーク管理 |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | 署名付きルールと参照データ |

</details>

</div>

<p align="center"><a href="#quickstart">使い始める</a> · <a href="#features">機能</a> · <a href="#details">詳細</a> · <a href="#whats-new">新機能と変更点</a></p>

<a id="whats-new"></a>

> **🆕 新機能 - 1.0.20 Beta (FLASH r1 · RAM r2)**
>
> - インターフェースの軽微な不具合を修正しました。
> - ライトとダークではキツネをカラーで、ナイトではロゴと操作ボタンをモノクロで表示します。
> - ライトテーマの配色を Android アプリと統一しました。設定項目の区切り線も、3 つのテーマすべてで統一しました。
> - サーバーの編集を取り消せるようになり、ルールを保存前に検証できます。PIN が違う場合は入力欄の丸だけが赤くなります。
> - プログラム情報を表にまとめ、フォント設定をテーマの上に配置しました。ダイアログはヘッダーの閉じるボタンで閉じられます。
> - スクロール中だけ上部バーの背景がぼかされます。ダークテーマに FoxHole VPN の配色を採用し、黒の配色は「夜」に改名しました。
> - フロントエンドの最適化。

<a id="quickstart"></a>

## 📦 インストール

自分のVPNサーバーやプロバイダーへ接続するクライアントです。利用可能なVPNサーバーやそのアクセス権は付属しません。

公開済みで検証されたリリースを選び、`RELEASE_TAG`をそのタグ、`MANIFEST_SHA256`を信頼できる`SHA256SUMS`のSHA-256、`INSTALLER_SHA256`を同じリリースの`install.sh`のSHA-256に置き換えてください。値の真正性は独立した方法で確認します。実行前にインストーラーを検証します。

### コンピューターから

ルーターの LAN に接続したコンピューターで、検証済みリリースのソースを開きます。インストーラーは Bash と OpenSSH を使います。Windows では Git for Windows を使います。

**macOS / Linux / Git Bash**

```sh
bash tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

**Windows PowerShell**

```powershell
& "$env:ProgramFiles\Git\bin\bash.exe" ./tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

同じリリースから `foxhole-openwrt-install.sh` をダウンロードして実行することもできます。署名済みのチェックサムで SHA-256 を確認し、コマンドから `tools/` を省きます。PowerShell の例は Git for Windows の既定のインストール先を使います。

インストーラーは既定の IPv4 ゲートウェイを使います。LAN 上の別のルーターを選ぶには `--host ROUTER_IP` を追加します。確認を求められたら SSH ホスト鍵を照合し、ログインしてルーター上でライセンスを確認します。

### ルーターの端末から

ルーター上で root として実行します。

```sh
( set -eu; release_tag='RELEASE_TAG'; manifest_sha256='MANIFEST_SHA256'; installer_sha256='INSTALLER_SHA256'; url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"; installer=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$installer"' EXIT; uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"; printf '%s  %s\n' "$installer_sha256" "$installer" | sha256sum -c -; sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_sha256" --apply )
```

`--apply` を使う対話式インストーラーは同意事項を表示し、`[y/N]` で確認します。既定は「いいえ」です。`sh install.sh --license` で内容を確認できます。非対話式インストールには、明示的に同意した後で `--accept-license` を指定する必要があります。電話の設定ウィザードでは、独立した同意欄は最初は未選択です。

コンパクトカタログでは、既定で **Hysteria2 クライアントのみ**を flash に保存します。
検証済みのローカルリリースバンドルでは、プロトコルを 1 つ選ぶか、フラグを組み合わせてください。

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` は `--wg` の別名です。他に認識されるフラグは `--vmess`、`--tuic`、
`--trojan`、`--shadowsocks`、`--naive`、`--anytls`、`--shadowtls`、`--socks`、`--http` です。
各モジュールは対象ファームウェアとプラットフォーム向けに公開されている必要があります。コンパクトカタログの`--all`は、対象向けに公開された全クライアントプロトコルを選びます。共通の保存方式が必要です。明示指定したプロトコルのモジュールがなければ拒否されます。旧schema 1では厳密に一致する構成が必要で、`--all`は認識可能な全プロトコルを意味します。

| 保存先 | 動作 |
| --- | --- |
| `--flash` | 再起動後もエンジンを flash に保持します。既定の設定です。 |
| `--ram` | エンジンのバイナリをRAMに読み込み、再起動後は必要に応じて再取得します。設定はflashに残ります。 |
| `--auto` | 全体の必要容量を満たせば flash を選び、それ以外は利用可能な RAM モジュール一式を選びます。 |

`--ram`保存モードは、実験的なnative RAM bootstrapとは別の機能です。永続的なbootstrap登録は無効のままで、コールドブートからの復旧は未検証、カスタムELFライブラリパスの許可問題も未解決です。[RAM bootstrapの制限](RAM-BOOTSTRAP.md)を参照してください。

`--apply`を省くと、インストールせずにバンドルを検査できます。互換性のないバンドルに合わせてカーネルパッケージを更新することはありません。コンパクトカタログの`--server`は、選択したカタログに互換性のある検証済み着信Hysteriaサーバーパッケージがある場合のみ利用でき、その場合に必要リソースへ加算されます。リモートアクセスを設定するまでは無効です。

<a id="features"></a>

## 🔌 対応 VPN プロトコル

ルーター向けに現在利用できる FoxHole VPN モジュール：

| プロトコル | インストールオプション | 説明 |
| --- | --- | --- |
| VLESS | `--vless` | VPNプロファイルで指定した設定を使い、互換性のあるVLESSサーバーへ接続するプロキシ型のクライアントです。 |
| Hysteria2 | `--hy2` | QUIC（UDP）を使ってHysteria2サーバーに接続します。選択したプロトコル専用のクライアントモジュールを使用します。 |
| WireGuard | `--wg` | WireGuardの対向ノードとのL3 IPトンネルです。プロファイルに鍵、アドレス、ネットワーク設定を指定します。 |

## 📋 必要条件

- apkパッケージマネージャーを備えたOpenWrt 25.12.5または25.12.6とroot権限。直接ダウンロードにはルーターのインターネット接続が必要ですが、ローカル`--bundle`は信頼できるLANで利用できます。
- 正確なファームウェア、対象、アーキテクチャ、選択したプロトコルに対応する公開済みパッケージ。現在のパッケージ・更新ポリシーは `x86/64` と `mediatek/filogic` を許可します。SDK ビルドや ARM アーキテクチャ名だけでは、すべてのルーターモデルとの互換性を証明できません。
- 検証済みパッケージ全体の予算に十分なフラッシュと RAM。パッケージを変更する前に、インストーラーが依存関係、カーネル ABI、一時領域を確認します。
- 信頼できるローカルネットワークからのアクセス。Androidでの検出と初期設定では、電話をルーターのWi-Fiに接続してください。

[v1.0.6リリース](https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/v1.0.6)にはBASE 1.0.6-r1とFoxHole Core 1.0.4のクライアントモジュールが含まれます。互換性のあるCore更新は個別にインストールできます。パッケージの提供と互換性はリリース、ファームウェア、ターゲットによって異なります。

ソースでの対応とクロスコンパイル済みバイナリだけでは、ルーターとの互換性を確認したことにはなりません。
真正性を確認済みのリリースカタログに含まれるパッケージだけをインストールできます。
着信接続用サーバーには、未使用の S2/OpenPGP パッケージに関する、精査済みの依存関係の指摘が 2 件残っています。
対象の厳密なビルド条件と例外の有効期限は、[リリース](RELEASE.md)に記載しています。

## 対応ルーター

| モデル | RAM | Flash | OpenWrt | パッケージのインストール先 |
|---|---|---|---|---|
| [Cudy WR3000 v1](https://www.cudy.com/products/wr3000-1-0) | 256 MB | 16 MB NOR | 25.12.5 | RAM のみ |
| [Cudy WR3000S v1](https://www.cudy.com/products/wr3000s-1-0) | 256 MB | 128 MB NAND | 25.12.6 | FLASH |

表には総容量を記載しています。インストール前に機種と空き容量を確認します。

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 使用とペアリング

PINを変更するとペアリングがリセットされ、端末の再接続が必要になります。VPNプロファイルと設定は保持されます。

**LuCI → Services → FoxHole OpenWRT Client → Panel** を開き、PIN を決めて VPN プロファイルを追加します。
ルールにより、端末、ドメイン、国別のトラフィックを VPN または直接接続へ振り分けられます。

`ACCESS_LOCAL_NETWORK` - ルーターの検索、設定、管理に使用します。Android 17（API 37）以降でアプリの対象 API も 37 以降の場合、LAN 操作の前にシステム権限を要求します。拒否すると該当する操作は行えません。

スマートフォンの設定では、接続中の Wi-Fi のプライベート IPv4 ゲートウェイでルーターを検索します。アドレスの手動入力も可能です。
ペアリング前にスマートフォンが SSH の識別情報とルーターのプライベート LAN TLS の識別情報を検証します。
既存の PIN は保持されます。管理用の接続先はプライベートのままです。
ペアリングを解除すると管理アクセスが削除されます。VPN 認証情報を失効させるには、リモートクライアントを別途削除してください。
従来の共有プロファイルの削除では、その記録だけが削除されます。外部 VPN プロバイダーが保持する認証情報は失効させられません。

リモートVPNクライアントの作成には、別途検証済みの着信Hysteriaサーバーパッケージが必要です。選択したリリースカタログに含まれる場合のみ`--server`でインストールできます。公開WANアドレスと外部から到達可能なUDPポートも必要です。条件を満たすと**VPN プロファイルを作成**でリモートクライアントを追加でき、既存クライアントを選択するとそのプロファイルが開きます。

自宅ネットワークでの VPN 自動切り替えは、fail-closed と所有権の確認を含む実際のルーティング検証が完了するまで無効のままです。

Android アプリでは：

Wi-Fi アイコンは物理的な Wi-Fi 接続のみを示し、SSID や位置情報へのアクセスは使いません。検索と新規設定・ペアリングには Wi-Fi が必要です。手動入力には利用可能な現在の Wi-Fi のプライベート IPv4 ゲートウェイが一度だけ入り、その後も編集できます。

自宅 VPN 経由で管理は独立した選択で、既存のペアリングごとに既定でオフです。公開 IP アドレスの確認（ルーターに公開 IP と受信 VPN サービスがあるという利用者の申告）と、利用可能なアクティブ VPN 経路も必要です。この確認はアドレスの割り当てやファイアウォール設定を行いません。アプリはその VPN ネットワーク経由で保存済みのプライベート接続先に、既存の固定 TLS 識別情報とペアリング認証で管理を試みます。WAN 管理ポートを開いたり、モバイル回線で新たに検索・ペアリングしたりはしません。

認証済みのペアリング済みルーターからアプリへ直接届く受信 VPN プロファイルにのみ、独立したアプリ連携メタデータが付きます。接続 URI、設定、QR 形式は変わりません。一般のウェブ・QR・プロバイダーのエクスポートには付きません。インポートしたヒントだけでは信頼を確立できません。

自動認識には、保存済みローカルプロファイル、現在の設定、選択したペアリングの一致に加え、そのプロファイルがアプリ自身の VPN で実際に接続中であることも必要です。実際の接続ごとに時間制限付き確認を一度行い、タイマー、自動再試行、プロバイダープロファイルの定期照会はありません。ペアリングを再試行は Wi-Fi・権限・PIN を使う明示的な手順です。認証成功までは元の記録を保持し、変更された証明書の識別情報を自動承認しません。

## 制限

- 国別ルールはIP範囲を使い、ドメインルールはルーターDNSに依存します。サイト所有者の国を特定したりHTTPSの内容を解析したりはしません。
- 有効なCore接続が予期せず失われると、そのVPN経路がブロックされます。別設定のKill switchは接続プロファイルがない場合のブロックを制御し、初期状態では無効です。
- ルール優先順位、ローカルアドレスの例外、着信サーバーの制限は[アーキテクチャ](ARCHITECTURE.md)を参照してください。

## 🧩 後からプロトコルを追加する

**ルーター VPN → プロトコル**で利用可能なプロトコルを選び、インストールを確認します。
ペアリング済みの Android アプリでも同じ操作ができます。
プロトコルごとに、個別のコンパクトな署名済みエンジンパッケージを使用します。
大きな汎用エンジンに無断で置き換わることはありません。

未使用のプロトコルを追加しても、現在の VPN は動作を続けます。
使用中のプロトコルを更新すると、再接続の確認が求められます。削除前に、そのプロトコルの使用を停止してください。
お使いのルーターの正確なターゲット向けに公開されたパッケージだけが表示されます。

## ♻️ 更新と削除

### 📥 FoxHole パッケージの更新

ウェブパネルまたはペアリング済みアプリの **設定 → FoxHole 更新** で、同じ認証付きトランザクションによる確認とインストールを行います。FoxHole パネル/runtime と選択済みのインストール済みクライアントプロトコルモジュールが対象で、FLASH/RAM の選択を保持します。新しいプロトコルは別途インストールします。プロファイルとペアリングは保持され、OpenWrt ファームウェアや他のシステムパッケージは更新しません。

新規インストールでは、所有者が PIN を設定するとパッケージの自動更新が有効になります。無効にするには、設定時にチェックを外すか、インストーラーに `--no-auto-update` を指定します。再ペアリング時は以前の選択が保持されます。後から設定で変更できます。

有効にすると、ルーターは毎日確認し、検証済み FoxHole パッケージ更新をインストールします。電話のペアリング解除でもこの設定は無効になりません。更新機能がない古いパッケージには、個別に検証した移行が必要です。[ソフトウェア更新](UPDATES.md)を参照してください。

ペアリング済みのルーターまたはスマートフォンの **ルーター VPN → プロトコル**で、プロトコルを追加・更新します。
コンパクトインストーラーは初回設定専用です。非公開の復旧用バックアップを保持し、DHCP 設定が変わっていないことを確認します。
ルーティング中にパッケージを削除する前に、[ロールバック・削除手順](ROLLBACK.md)を使用してください。
検証済みのリリースパッケージを使用してください。
旧インストーラーとARM専用ダウンロードは使用しません。FoxHole CoreはHysteria2に対応します。既存のlegacyプロファイルは別のHysteriaランタイムを使い、Coreへ自動移行されません。更新前に稼働中のlegacy Hysteria接続を手動停止してください。

- **利用手順:** [CLI](CLI.md) · [Updates](UPDATES.md) · [Rollback](ROLLBACK.md)
- **アーキテクチャ:** [Architecture](ARCHITECTURE.md) · [Mobile networks](MOBILE-NETWORKS.md) · [Backup](BACKUP-ARCHITECTURE.md) · [Profile origin](PROFILE-ORIGIN.md)
- **保守:** [Release](RELEASE.md) · [Bundle transport](BUNDLE-TRANSPORT.md) · [RAM install](RAM-INSTALL.md) · [Bootstrap](RAM-BOOTSTRAP.md) · [Prerequisites](RAM-PREREQUISITES.md) · [RAM updates](RAM-UPDATE-CONTROLLER.md) · [Engine origin](engine-release-origin.md) · [Security](../SECURITY.md)

### FoxHole のアンインストール

LuCI の **サービス → FoxHole OpenWRT Client → Uninstall FoxHole** を開き、対象を確認してください。ルーターの root 端末では次のコマンドを実行します。

```sh
/usr/libexec/foxhole-uninstall
```

コマンドは削除内容を表示して確認を求めます。FLASH 版では VPN を切断して基本パッケージを削除します。管理対象の RAM 版では、自動起動を無効にした後で OpenWrt を再起動してください。再起動後も FLASH 版が残る場合は別途削除してください。ネットワーク設定、プロファイル、ペアリングは保持されます。FLASH に保存済みの復元用キャッシュは保持されます。

## 🤝 開発への参加

不具合報告や変更提案は[Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues)へお願いします。

## 💖 開発を支援する

私たちは、開発にAIツールを使用しながら、すべて自分たちの時間と資源でFoxHole OpenWrtを開発・保守しています。皆さまのご支援により、プロジェクトにより多くの時間を充て、開発を加速できます。

<a id="cryptocurrency-wallets"></a>

### 🪙 暗号資産ウォレット

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

## 📄 ライセンス

[ライセンス](../LICENSE) · [サードパーティのライセンス](../THIRD_PARTY_NOTICES.md)
