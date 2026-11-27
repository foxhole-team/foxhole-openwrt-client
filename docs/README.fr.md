<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

Profils VPN, règles de routage et interface simple pour les routeurs OpenWrt.
Les connexions VPN sortantes utilisent [FoxHole Core](https://github.com/foxhole-team/foxhole-core).
Chaque protocole choisi utilise un module client distinct dans une installation compacte. La version 1.0.8 ajoute un paquet facultatif et vérifié séparément pour le serveur Hysteria2 entrant. L’accès distant exige une adresse WAN publique et statique ainsi qu’un port UDP accessible depuis l’extérieur.

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

[🇬🇧 English](../README.md) · [🇷🇺 Русский](README.ru.md) · [🇩🇪 Deutsch](README.de.md) · [🇫🇷 **Français**](README.fr.md) · [🇪🇸 Español](README.es.md) · [🇯🇵 日本語](README.ja.md) · [🇨🇳 简体中文](README.zh.md) · [🇸🇦 العربية](README.ar.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<a id="ecosystem"></a>
<a id="-écosystème-foxhole"></a>

<div align="center">
  <strong>FoxHole ecosystem</strong><br>
  <a href="https://github.com/foxhole-team/foxhole-guard">FoxHole Guard</a> ·
  <a href="https://github.com/foxhole-team/foxhole-vpn">FoxHole VPN</a> ·
  <a href="https://github.com/foxhole-team/foxhole-core">FoxHole Core</a> ·
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client"><strong>FoxHole OpenWRT</strong></a> ·
  <a href="https://github.com/foxhole-team/foxhole-db">FoxHole DB</a>

<details>
<summary>Rôles des projets</summary>

| Projet | Rôle |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android : VPN, Tor/I2P, règles de trafic et surveillance locale |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android : client VPN simple et gestion OpenWrt appairée |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | Cœur réseau Rust commun ; fonctions selon la compilation |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | VPN de routeur et gestion du réseau local |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Règles signées et données de référence |

</details>

</div>

<p align="center"><a href="#quickstart">Démarrer</a> · <a href="#features">Fonctions</a> · <a href="#details">Détails</a> · <a href="#whats-new">Nouveautés</a></p>

<a id="whats-new"></a>

> **🆕 Nouveautés - 1.0.13 Beta (FLASH r1 · RAM r2)**
>
> - Installez le paquet par SSH depuis macOS, Linux ou Windows avec le programme Bash. Après une nouvelle installation, les mises à jour automatiques du paquet sont activées et peuvent être désactivées.
> - Les mises à jour vérifient l’API du routeur et tentent de restaurer la version précédente si la vérification échoue. La gestion du serveur VPN domestique et la création du premier client ont été corrigées.
> - Importez les abonnements Hysteria 2, VLESS et WireGuard compatibles dans LuCI ou envoyez-les depuis Guard ou VPN. Le routeur actualise automatiquement les abonnements compatibles.
> - Jeux sans VPN utilise un interrupteur standard dans les paramètres. Le routage s’ouvre depuis Ajouter. Les flèches d’ouverture et de fermeture ont des angles nets.
> - Le journal a une nouvelle icône d’actualisation et affiche les dix derniers événements VPN en RAM. L’état logiciel affiche Hysteria 2 lorsqu’il est installé séparément.

<a id="quickstart"></a>

## 📦 Installation

Ce client se connecte à votre propre serveur ou fournisseur VPN. Aucun serveur VPN prêt à l’emploi ni accès associé n’est inclus.

Choisissez une version publiée et vérifiée. Remplacez `RELEASE_TAG` par son tag, `MANIFEST_SHA256` par le SHA-256 de confiance de son `SHA256SUMS`, et `INSTALLER_SHA256` par le SHA-256 de son `install.sh`. Authentifiez ces valeurs indépendamment. L’installateur est vérifié avant exécution .

### Depuis un ordinateur

Ouvrez les sources de la version vérifiée sur un ordinateur du réseau local du routeur. Le programme utilise Bash et OpenSSH. Sous Windows, utilisez Git for Windows.

**macOS / Linux / Git Bash**

```sh
bash tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

**Windows PowerShell**

```powershell
& "$env:ProgramFiles\Git\bin\bash.exe" ./tools/foxhole-openwrt-install.sh --release RELEASE_TAG --manifest-sha256 MANIFEST_SHA256 --installer-sha256 INSTALLER_SHA256 --auto
```

Vous pouvez aussi télécharger `foxhole-openwrt-install.sh` depuis cette version. Vérifiez son SHA-256 avec les sommes signées et omettez `tools/` dans la commande. L’exemple PowerShell utilise le chemin d’installation par défaut de Git for Windows.

Le programme utilise la passerelle IPv4 par défaut. Ajoutez `--host ROUTER_IP` pour choisir un autre routeur du réseau local. Vérifiez la clé d’hôte SSH quand elle est demandée, connectez-vous et lisez la licence sur le routeur.

### Depuis le terminal du routeur

Exécutez la commande sur le routeur en tant que root.

```sh
( set -eu; release_tag='RELEASE_TAG'; manifest_sha256='MANIFEST_SHA256'; installer_sha256='INSTALLER_SHA256'; url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"; installer=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$installer"' EXIT; uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"; printf '%s  %s\n' "$installer_sha256" "$installer" | sha256sum -c -; sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_sha256" --apply )
```

Avec `--apply`, l’installateur interactif affiche l’accord et demande `[y/N]`, avec Non par défaut. Consultez-le avec `sh install.sh --license`. L’installation non interactive exige `--accept-license` après acceptation explicite. Dans l’assistant du téléphone, le choix distinct de consentement est initialement décoché.

Pour les catalogues compacts, la valeur par défaut est **le client Hysteria2
uniquement**, stocké en mémoire flash. Avec un lot de publication local vérifié, choisissez un protocole ou combinez les options :

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` est un alias de `--wg`. Autres options reconnues : `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Chaque module doit être publié pour le micrologiciel et la cible. Dans un catalogue compact, `--all` sélectionne tous les protocoles clients publiés pour la cible. Les modules sélectionnés doivent partager un mode de stockage pris en charge. Un protocole explicitement demandé est refusé si son module manque. Les anciens catalogues schema 1 exigent une variante exacte ; `--all` y signifie tous les protocoles reconnus.

| Stockage | Comportement |
| --- | --- |
| `--flash` | Le moteur reste en mémoire flash après un redémarrage. Mode par défaut. |
| `--ram` | Le binaire du moteur est chargé en RAM et récupéré à nouveau si nécessaire après un redémarrage. Les paramètres restent en mémoire flash. |
| `--auto` | Choisit la mémoire flash si le budget complet tient, sinon un ensemble de modules RAM disponible. |

Le mode de stockage `--ram` est distinct du bootstrap RAM natif expérimental. L’enrôlement persistant reste désactivé, la récupération après démarrage à froid n’est pas qualifiée et l’admission du chemin personnalisé des bibliothèques ELF reste non résolue. Voir les [limites du bootstrap RAM](RAM-BOOTSTRAP.md).

Retirez `--apply` pour vérifier le lot sans l’installer. Les paquets du noyau ne sont jamais mis à niveau pour adapter un lot incompatible. Pour les catalogues compacts, `--server` n’est disponible que si le catalogue choisi contient un paquet compatible et vérifié pour le serveur Hysteria entrant ; il est alors ajouté au budget de ressources. Le serveur reste désactivé jusqu’à la configuration de l’accès distant.

<a id="features"></a>

## 🔌 Protocoles VPN pris en charge

Modules VPN FoxHole actuellement disponibles pour le routeur :

| Protocole | Option d’installation | Description |
| --- | --- | --- |
| VLESS | `--vless` | Connexion proxy à un serveur VLESS compatible avec les paramètres définis dans le profil VPN. |
| Hysteria2 | `--hy2` | Connexion à un serveur Hysteria2 via QUIC/UDP, assurée par son module client distinct. |
| WireGuard | `--wg` | Tunnel IP de couche 3 vers un pair WireGuard ; le profil définit clés, adresses et paramètres réseau. |

## 📋 Prérequis

- OpenWrt 25.12.5 ou 25.12.6 avec le gestionnaire de paquets apk et l’accès root. Les téléchargements directs nécessitent Internet sur le routeur ; un `--bundle` local ne demande qu’un LAN de confiance.
- Des paquets publiés pour le micrologiciel, la cible, l’architecture et les protocoles exacts. La politique actuelle des paquets et mises à jour admet `x86/64` et `mediatek/filogic` ; une compilation SDK ou un nom d’architecture ARM ne valide pas tous les modèles de routeur.
- Assez de mémoire flash et de RAM pour le budget complet et vérifié des paquets. Avant toute modification, l’installateur contrôle les dépendances, l’ABI du noyau et l’espace temporaire.
- Accès depuis un réseau local de confiance. Pour la découverte et la première configuration Android, connectez le téléphone au Wi-Fi du routeur.

La [version v1.0.6](https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/v1.0.6) comprend BASE 1.0.6-r1 et les modules clients FoxHole Core 1.0.4. Les mises à jour Core compatibles peuvent être installées séparément. Leur disponibilité et leur compatibilité dépendent de la version, du firmware et de la cible.

La prise en charge dans les sources et un binaire compilé pour une autre
architecture ne suffisent pas à établir la compatibilité du routeur. Seuls les
paquets figurant dans un catalogue de publication authentifié peuvent être installés.
Le serveur entrant conserve deux constats examinés concernant des dépendances
S2/OpenPGP inutilisées ; les vérifications du build exact et l’échéance des exceptions sont documentées dans [Publication](RELEASE.md).

## Routeurs pris en charge

| Modèle | RAM | Flash | OpenWrt | Installation du paquet |
|---|---|---|---|---|
| [Cudy WR3000 v1](https://www.cudy.com/products/wr3000-1-0) | 256 Mo | 16 Mo NOR | 25.12.5 | RAM uniquement |
| [Cudy WR3000S v1](https://www.cudy.com/products/wr3000s-1-0) | 256 Mo | 128 Mo NAND | 25.12.6 | FLASH |

Le tableau indique la capacité totale. Avant l’installation, l’assistant vérifie le modèle exact et l’espace disponible.

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 Utilisation et appairage

Changer le PIN réinitialise les appairages : le téléphone devra être reconnecté, tandis que les profils VPN et les paramètres sont conservés.

Ouvrez **LuCI → Services → FoxHole OpenWRT Client → Panel**, choisissez un PIN et ajoutez un profil VPN.
Les règles peuvent diriger le trafic des appareils, domaines et pays vers le VPN ou une connexion directe.

`ACCESS_LOCAL_NETWORK` - recherche, configuration et gestion des routeurs. Sous Android 17 (API 37) ou ultérieur, si l’application cible l’API 37 ou ultérieure, elle demande l’autorisation système avant les actions LAN. Un refus bloque ces actions.

La configuration du téléphone cherche le routeur à la passerelle IPv4 privée du Wi-Fi
connecté ; une adresse peut aussi être saisie manuellement. Avant l’appairage, le téléphone
vérifie l’identité SSH et l’identité TLS privée du routeur sur le LAN. Un PIN
existant est conservé. L’adresse de gestion reste privée.
Le désappairage retire l’accès d’administration. Supprimez séparément le client
distant pour révoquer ses identifiants VPN. La suppression d’un ancien profil
partagé retire uniquement son enregistrement ; elle ne peut pas révoquer les identifiants détenus par un fournisseur VPN externe.

La création de clients VPN distants exige un paquet vérifié séparément pour le serveur Hysteria entrant, installable avec `--server` uniquement s’il figure dans le catalogue de la version choisie. Une adresse WAN publique et un port UDP accessible de l’extérieur sont également nécessaires. **Créer un profil VPN** ajoute alors un client distant ; sélectionner un client existant ouvre son profil.

Le basculement VPN automatique sur le réseau domestique reste désactivé jusqu’à
la validation réelle du routage, y compris les contrôles de fermeture en cas d’échec et de propriété du tunnel.

Dans les applications Android :

L’icône Wi-Fi indique uniquement une connexion Wi-Fi physique, sans SSID ni accès à la localisation. La recherche et toute nouvelle configuration/association exigent le Wi-Fi. L’adresse manuelle est préremplie une fois avec la passerelle IPv4 privée du Wi-Fi actuel, si disponible, et reste modifiable.

Gérer via le VPN domestique est un choix distinct, DÉSACTIVÉ par défaut pour chaque association existante. Il exige aussi votre confirmation Adresse IP publique (le routeur possède une IP publique et un service VPN entrant) et une route VPN active utilisable. Cette confirmation n’attribue aucune adresse et ne configure pas le pare-feu. L’application peut tenter la gestion à l’adresse privée enregistrée via ce réseau VPN avec l’identité TLS épinglée et l’authentification associée existantes ; elle n’ouvre aucun port de gestion WAN et ne permet pas de nouvelle recherche/association via le réseau mobile.

Seuls les profils VPN entrants transmis directement à l’application par un routeur associé et authentifié reçoivent des métadonnées distinctes de liaison avec l’application. URI de connexion, configuration et formats QR restent inchangés. Les exports génériques web/QR/fournisseurs restent sans marque ; des indications importées ne créent pas de confiance à elles seules.

La reconnaissance automatique exige aussi le profil local enregistré correspondant, sa configuration actuelle et l’association sélectionnée, avec ce profil réellement connecté via le VPN de l’application. Une vérification bornée est effectuée par connexion réelle, sans minuteur, nouvelle tentative automatique ni interrogation des profils fournisseurs. Réessayer l’association est une procédure explicite Wi-Fi/autorisation/PIN : l’ancien enregistrement est conservé jusqu’à l’authentification réussie, sans accepter silencieusement une identité de certificat différente.

## Limites

- Les règles de pays utilisent des plages IP et les règles de domaine dépendent du DNS du routeur. Elles ne déterminent pas le pays du propriétaire du site et n’analysent pas le contenu HTTPS.
- La perte inattendue de la connexion Core active bloque son routage VPN. Le réglage Kill switch distinct contrôle le blocage sans profil actif et est désactivé par défaut.
- Les priorités, exceptions locales et limites du serveur entrant figurent dans l’[architecture](ARCHITECTURE.md).

## 🧩 Ajouter un protocole ultérieurement

Dans **VPN du routeur → Protocoles**, sélectionnez un protocole disponible et
confirmez son installation. Les mêmes commandes sont accessibles dans l’application
Android appairée. Chaque protocole utilise son propre paquet moteur compact et
signé ; aucun remplacement silencieux par un moteur universel plus volumineux n’a lieu.

L’ajout d’un protocole inutilisé laisse le VPN actuel fonctionner. La mise à jour
du protocole actif demande une reconnexion. Cessez d’utiliser un protocole avant
de le supprimer. Seuls les paquets publiés pour la cible exacte de votre routeur sont proposés.

## ♻️ Mise à jour et suppression

### 📥 Mises à jour des paquets FoxHole

Dans **Paramètres → Mise à jour FoxHole** de l’interface web ou de l’application associée, la recherche et l’installation utilisent la même transaction authentifiée. Elle met à jour le panneau/runtime FoxHole et les modules de protocoles clients installés et sélectionnés, en conservant leur mode FLASH/RAM. Les nouveaux protocoles sont installés séparément. Profils et association sont conservés ; ni le micrologiciel OpenWrt ni les autres paquets système ne sont mis à jour.

Lors d’une nouvelle installation, les mises à jour automatiques du paquet sont activées une fois le code PIN du propriétaire défini. Décochez la case pendant la configuration ou passez `--no-auto-update` au programme d’installation. Une nouvelle association conserve le choix précédent. Vous pouvez le modifier dans les paramètres.

Si elle est activée, le routeur vérifie chaque jour et installe les mises à jour vérifiées des paquets FoxHole. Dissocier le téléphone ne désactive pas cette politique. Les anciens paquets dépourvus de cet outil nécessitent une migration vérifiée séparément. Voir les [mises à jour logicielles](UPDATES.md).

Ajoutez ou mettez à jour les protocoles via **VPN du routeur → Protocoles** sur le
routeur ou le téléphone appairé. L’installateur compact sert uniquement à la
configuration initiale. Il conserve des sauvegardes de récupération privées et
vérifie que les paramètres DHCP restent inchangés. Avant de supprimer des paquets
pendant que le routage est actif, suivez les instructions de [retour arrière/suppression](ROLLBACK.md).
Utilisez des paquets de publication vérifiés. Les anciens installateurs et téléchargements réservés à ARM ne sont pas utilisés. FoxHole Core prend en charge Hysteria2. Les profils legacy conservent le moteur Hysteria distinct, sans migration automatique vers Core. Arrêtez manuellement une connexion Hysteria legacy active avant la mise à jour.

- **Instructions:** [CLI](CLI.md) · [Updates](UPDATES.md) · [Rollback](ROLLBACK.md)
- **Architecture:** [Architecture](ARCHITECTURE.md) · [Mobile networks](MOBILE-NETWORKS.md) · [Backup](BACKUP-ARCHITECTURE.md) · [Profile origin](PROFILE-ORIGIN.md)
- **Maintenance:** [Release](RELEASE.md) · [Bundle transport](BUNDLE-TRANSPORT.md) · [RAM install](RAM-INSTALL.md) · [Bootstrap](RAM-BOOTSTRAP.md) · [Prerequisites](RAM-PREREQUISITES.md) · [RAM updates](RAM-UPDATE-CONTROLLER.md) · [Engine origin](engine-release-origin.md) · [Security](../SECURITY.md)

### Désinstaller FoxHole

Dans LuCI, ouvrez **Services → FoxHole OpenWRT Client → Uninstall FoxHole** et confirmez la désinstallation indiquée. Dans un terminal du routeur ouvert en tant que root, exécutez

```sh
/usr/libexec/foxhole-uninstall
```

La commande affiche le plan et demande confirmation. Sur FLASH, elle déconnecte le VPN et supprime le paquet de base. Pour une installation en RAM gérée, redémarrez OpenWrt après la désactivation du démarrage automatique. Si une copie FLASH subsiste, supprimez-la séparément. Les paramètres réseau, profils et associations sont conservés. Tout cache de récupération déjà présent sur la FLASH est conservé.

## 🤝 Contribuer

Signalez les erreurs et proposez des modifications via [Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues).

## 💖 Soutenir le développement

Nous développons et maintenons FoxHole OpenWrt entièrement avec notre propre temps et nos propres ressources, en utilisant des outils d’IA pendant le développement. Votre soutien nous aide à consacrer plus de temps au projet et à accélérer le développement.

<a id="cryptocurrency-wallets"></a>

### 🪙 Portefeuilles de cryptomonnaies

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

## 📄 Licences

[Licence](../LICENSE) · [Licences des composants tiers](../THIRD_PARTY_NOTICES.md)
