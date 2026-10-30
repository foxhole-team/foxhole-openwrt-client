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
</p>

# FoxHole OpenWrt

OpenWrt ルーター向けの VPN プロファイル、ルーティングルール、シンプルな管理パネル。
外向きの VPN 接続には [FoxCore](https://github.com/foxhole-team/foxhole-core) を使用します。
コンパクト構成では、選択したプロトコルごとに個別のクライアントモジュールを使います。
オプションの Hysteria サーバーで、お使いの端末からの接続を受け入れられます。

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

## 🔌 対応 VPN プロトコル

ルーター向けに現在利用できる FoxHole VPN モジュール：

| プロトコル | インストールオプション |
| --- | --- |
| VLESS | `--vless` |
| Hysteria2 | `--hy2` |
| WireGuard | `--wg` |

## 📋 必要条件

- APK を使う OpenWrt 25.12.5、root 権限、インターネット接続。
- 正確なファームウェア、対象、アーキテクチャ、選択したプロトコルに対応する公開済みパッケージ。現在のパッケージ・更新ポリシーは `x86/64` と `mediatek/filogic` を許可します。SDK ビルドや ARM アーキテクチャ名だけでは、すべてのルーターモデルとの互換性を証明できません。
- 検証済みパッケージ全体の予算に十分なフラッシュと RAM。パッケージを変更する前に、インストーラーが依存関係、カーネル ABI、一時領域を確認します。
- 信頼できる LAN からのアクセス。新しいルーターで Wi-Fi が無効なら、先に有効にしてください。

このパブリックベータでは、送信用 VPN モジュールに FoxHole Core 1.0.1 を使用します。
ソースでの対応とクロスコンパイル済みバイナリだけでは、ルーターとの互換性を確認したことにはなりません。
真正性を確認済みのリリースカタログに含まれるパッケージだけをインストールできます。
着信接続用サーバーには、未使用の S2/OpenPGP パッケージに関する、精査済みの依存関係の指摘が 2 件残っています。
対象の厳密なビルド条件と例外の有効期限は、[リリース](RELEASE.md)に記載しています。

## 📦 インストール

公開済みでレビュー済みのリリースタグと、その `SHA256SUMS` の真正性を独立した方法で確認した SHA-256 を使用してください。
次のコマンドは、実行前にインストーラーを検証します。

```sh
(set -eu; url='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/RELEASE_TAG'; f=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$f"' EXIT; uclient-fetch -q -T 60 -O "$f" "$url/install.sh"; printf '%s  %s\n' 'fb0a2bad91a1eebd3591801f79dd6b83fc70bf94ddc1b8d6577f94519de1d1d9' "$f" | sha256sum -c -; sh "$f" --base-url "$url" --manifest-sha256 MANIFEST_SHA256 --apply)
```

`--apply` を使う対話式インストーラーは同意事項を表示し、`[y/N]` で確認します。既定は「いいえ」です。`sh install.sh --license` で内容を確認できます。非対話式インストールには、明示的に同意した後で `--accept-license` を指定する必要があります。電話の設定ウィザードでは、独立した同意欄は最初は未選択です。

コンパクトカタログでは、既定で **Hysteria2 クライアントのみ**を flash に保存します。
検証済みのローカルリリースバンドルでは、プロトコルを 1 つ選ぶか、フラグを組み合わせてください。

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --server --ram --apply
```

`-wg` は `--wg` の別名です。他に認識されるフラグは `--vmess`、`--tuic`、
`--trojan`、`--shadowsocks`、`--naive`、`--anytls`、`--shadowtls`、`--socks`、`--http` です。
コンパクトカタログでは、同じ保存モードでリリース済みモジュールを組み合わせます。
選択した各モジュールが、お使いのファームウェアとターゲットで提供されている必要があります。
`--all` は認識される全プロトコルを要求し、1 つでもモジュールがなければ拒否されます。
旧 schema 1 カタログでは、厳密に一致する単一のバリアントが必要です。

| 保存先 | 動作 |
| --- | --- |
| `--flash` | 再起動後もエンジンを flash に保持します。既定の設定です。 |
| `--ram` | エンジンは RAM を使い、再起動後に固定されたバイナリをダウンロードします。設定は flash に残ります。 |
| `--auto` | 全体の必要容量を満たせば flash を選び、それ以外は利用可能な RAM モジュール一式を選びます。 |

`--apply` を省くと、インストールせずに選択したバンドルを確認できます。
互換性のないバンドルを使うためにカーネルパッケージを更新することはありません。
コンパクトカタログでは、`--server` により着信接続用 Hysteria サーバーの必要リソースを加算します。
サーバーはリモートアクセスを設定するまで無効のままです。

## 🔗 使用とペアリング

**LuCI → Services → FoxHole** を開き、PIN を決めて VPN プロファイルを追加します。
ルールにより、端末、ドメイン、国別のトラフィックを VPN または直接接続へ振り分けられます。

`ACCESS_LOCAL_NETWORK` - ルーターの検索、設定、管理に使用します。Android 17（API 37）以降でアプリの対象 API も 37 以降の場合、LAN 操作の前にシステム権限を要求します。拒否すると該当する操作は行えません。

スマートフォンの設定では、接続中の Wi-Fi のプライベート IPv4 ゲートウェイでルーターを検索します。アドレスの手動入力も可能です。
ペアリング前にスマートフォンが SSH の識別情報とルーターのプライベート LAN TLS の識別情報を検証します。
既存の PIN は保持されます。管理用の接続先はプライベートのままです。
ペアリングを解除すると管理アクセスが削除されます。VPN 認証情報を失効させるには、リモートクライアントを別途削除してください。
従来の共有プロファイルの削除では、その記録だけが削除されます。外部 VPN プロバイダーが保持する認証情報は失効させられません。

リモートアクセスには、`--server` で選択した Hysteria サーバーが必要です。
パブリック WAN アドレスを持つルーターでは、**VPN プロファイルを作成**でリモートクライアントを追加します。
クライアントを選択すると、その既存のプロファイルが開きます。
UDP リスナーには、自宅ネットワークの外部からも到達できる必要があります。
自宅ネットワークでの VPN 自動切り替えは、fail-closed と所有権の確認を含む実際のルーティング検証が完了するまで無効のままです。

Android アプリでは：

Wi-Fi アイコンは物理的な Wi-Fi 接続のみを示し、SSID や位置情報へのアクセスは使いません。検索と新規設定・ペアリングには Wi-Fi が必要です。手動入力には利用可能な現在の Wi-Fi のプライベート IPv4 ゲートウェイが一度だけ入り、その後も編集できます。

自宅 VPN 経由で管理は独立した選択で、既存のペアリングごとに既定でオフです。公開 IP アドレスの確認（ルーターに公開 IP と受信 VPN サービスがあるという利用者の申告）と、利用可能なアクティブ VPN 経路も必要です。この確認はアドレスの割り当てやファイアウォール設定を行いません。アプリはその VPN ネットワーク経由で保存済みのプライベート接続先に、既存の固定 TLS 識別情報とペアリング認証で管理を試みます。WAN 管理ポートを開いたり、モバイル回線で新たに検索・ペアリングしたりはしません。

認証済みのペアリング済みルーターからアプリへ直接届く受信 VPN プロファイルにのみ、独立したアプリ連携メタデータが付きます。接続 URI、設定、QR 形式は変わりません。一般のウェブ・QR・プロバイダーのエクスポートには付きません。インポートしたヒントだけでは信頼を確立できません。

自動認識には、保存済みローカルプロファイル、現在の設定、選択したペアリングの一致に加え、そのプロファイルがアプリ自身の VPN で実際に接続中であることも必要です。実際の接続ごとに時間制限付き確認を一度行い、タイマー、自動再試行、プロバイダープロファイルの定期照会はありません。ペアリングを再試行は Wi-Fi・権限・PIN を使う明示的な手順です。認証成功までは元の記録を保持し、変更された証明書の識別情報を自動承認しません。

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

CLI/backend から直接インストールした場合、自動更新は既定でオフです。電話からの新規設定では、独立した表示付きチェックボックスが最初からオンです。希望しない場合はオフにしてください。選択した更新設定はインストールとペアリング後に保存されます。既存ルーターのペアリングでは設定を保持し、後から設定画面で変更できます。

有効にすると、ルーターは毎日確認し、検証済み FoxHole パッケージ更新をインストールします。電話のペアリング解除でもこの設定は無効になりません。更新機能がない古いパッケージには、個別に検証した移行が必要です。[ソフトウェア更新](UPDATES.md)を参照してください。

ペアリング済みのルーターまたはスマートフォンの **ルーター VPN → プロトコル**で、プロトコルを追加・更新します。
コンパクトインストーラーは初回設定専用です。非公開の復旧用バックアップを保持し、DHCP 設定が変わっていないことを確認します。
ルーティング中にパッケージを削除する前に、[ロールバック・削除手順](ROLLBACK.md)を使用してください。
検証済みのリリースパッケージを使用してください。
過去の旧インストーラーや ARM 専用ダウンロードは対象外です。既存の HY2 プロファイルは Core で引き続き使用できます。

[コマンド](CLI.md) · [アーキテクチャ](ARCHITECTURE.md) ·
[ビルドとリリース](RELEASE.md) · [セキュリティ](../SECURITY.md)

## 💖 開発を支援する

私たちはAIツールの助けを借りながら、すべて自分たちの時間と資源でFoxHole OpenWrtを開発・保守しています。皆さまのご支援により、プロジェクトにより多くの時間を充て、開発を加速できます。

[プロジェクトを支援する - 暗号資産ウォレット](#cryptocurrency-wallets)

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
