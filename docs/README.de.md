<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

VPN-Profile, Routingregeln und eine einfache Oberfläche für OpenWrt-Router.
Ausgehende VPN-Verbindungen nutzen [FoxHole Core](https://github.com/foxhole-team/foxhole-core).
Kompakte Installationen verwenden ein eigenes Clientmodul je ausgewähltem Protokoll. Version 1.0.8 ergänzt ein optionales, separat geprüftes Paket für einen eingehenden Hysteria2-Server. Für den Fernzugriff sind eine öffentliche statische WAN-Adresse und ein von außen erreichbarer UDP-Port erforderlich.

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

[🇬🇧 English](../README.md) · [🇷🇺 Русский](README.ru.md) · [🇩🇪 **Deutsch**](README.de.md) · [🇫🇷 Français](README.fr.md) · [🇪🇸 Español](README.es.md) · [🇯🇵 日本語](README.ja.md) · [🇨🇳 简体中文](README.zh.md) · [🇸🇦 العربية](README.ar.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<a id="ecosystem"></a>
<a id="-foxhole-ökosystem"></a>

<div align="center">
  <strong>FoxHole ecosystem</strong><br>
  <a href="https://github.com/foxhole-team/foxhole-guard">FoxHole Guard</a> ·
  <a href="https://github.com/foxhole-team/foxhole-vpn">FoxHole VPN</a> ·
  <a href="https://github.com/foxhole-team/foxhole-core">FoxHole Core</a> ·
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client"><strong>FoxHole OpenWRT</strong></a> ·
  <a href="https://github.com/foxhole-team/foxhole-db">FoxHole DB</a>

<details>
<summary>Rollen der Projekte</summary>

| Projekt | Aufgabe |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, Verkehrsregeln und lokale Überwachung |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: einfacher VPN-Client und gekoppelte OpenWrt-Verwaltung |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | Gemeinsamer Rust-Netzwerkkern; Umfang je Build |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | Router-VPN und Verwaltung des lokalen Netzes |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Signierte Regeln und Referenzdaten |

</details>

</div>

<p align="center"><a href="#quickstart">Einstieg</a> · <a href="#features">Funktionen</a> · <a href="#details">Details</a> · <a href="#whats-new">Was ist neu</a></p>

<a id="whats-new"></a>

> **🆕 Neuigkeiten - 1.0.8 Beta**
>
> - Unterstützung für OpenWrt 25.12.6 hinzugefügt
> - Optimierung der Benutzeroberfläche
> - Optionales, separat geprüftes Hysteria2-Serverpaket ergänzt (öffentliche statische IP erforderlich)
> - Hilfe, Updateprüfung und Informationen zur Anwendung überarbeitet
> - Journal nur im FLASH mit bis zu 30 Tagen Ringspeicherung und begrenztem Speicherverbrauch
> - Routerverwaltung über VPN und Neuinstallation des RAM-Pakets verbessert
>
> Begleitende Apps: FoxHole VPN 1.0.6 und Guard 1.0.7 korrigieren die Erstinstallation und Einrichtung des Routers. Guard aktualisiert außerdem die Tor-Transporte Lyrebird und conjure-client
>
> Die dauerhafte Bootstrap-Aktivierung bleibt deaktiviert. Die Wiederherstellung nach einem Kaltstart ist nicht bestätigt; das Problem bei der Prüfung des ELF-Bibliothekspfads besteht weiterhin

<a id="features"></a>

## 🔌 Unterstützte VPN-Protokolle

Aktuelle FoxHole-VPN-Module für den Router:

| Protokoll | Installationsoption | Beschreibung |
| --- | --- | --- |
| VLESS | `--vless` | Proxyverbindung zu einem kompatiblen VLESS-Server mit den Parametern des VPN-Profils. |
| Hysteria2 | `--hy2` | Verbindung zu einem Hysteria2-Server über QUIC/UDP mit einem eigenen Clientmodul. |
| WireGuard | `--wg` | IP-Tunnel auf Schicht 3 zu einem WireGuard-Peer; das Profil legt Schlüssel, Adressen und Netzparameter fest. |

## 📋 Voraussetzungen

- OpenWrt 25.12.5 oder 25.12.6 mit Paketmanager apk und Root-Zugriff. Direkte Downloads benötigen Internet am Router; ein lokales `--bundle` benötigt nur ein vertrauenswürdiges LAN.
- Veröffentlichte Pakete für die genaue Firmware, Zielplattform, Architektur und ausgewählten Protokolle. Die aktuelle Paket-/Updaterichtlinie lässt `x86/64` und `mediatek/filogic` zu; ein SDK-Build oder ARM-Architekturname bestätigt nicht jedes Routermodell.
- Genügend Flash und RAM für das vollständige geprüfte Paketbudget. Vor Paketänderungen prüft der Installer Abhängigkeiten, Kernel-ABI und Zwischenspeicherplatz.
- Zugriff aus einem vertrauenswürdigen lokalen Netz. Für Suche und Ersteinrichtung unter Android das Telefon mit dem WLAN des Routers verbinden.

Der [Release v1.0.6](https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/v1.0.6) enthält BASE 1.0.6-r1 und Clientmodule mit FoxHole Core 1.0.4. Kompatible Core-Updates können separat installiert werden. Verfügbarkeit und Kompatibilität hängen von Release, Firmware und Target ab.

Unterstützung im Quellcode und eine kreuzkompilierte Binärdatei
allein belegen keine Routerkompatibilität. Installierbar sind nur Pakete aus
einem authentifizierten Release-Katalog. Beim eingehenden Server bestehen zwei
geprüfte Abhängigkeitsbefunde in ungenutzten S2/OpenPGP-Paketen; Prüfungen für den
exakten Build und die Gültigkeitsfrist stehen unter [Release](RELEASE.md).

<a id="quickstart"></a>

## 📦 Installation

Dieser Client verbindet sich mit Ihrem eigenen VPN-Server oder Anbieter. Fertige VPN-Server und deren Zugang sind nicht enthalten.

Wählen Sie eine veröffentlichte, geprüfte Version. Ersetzen Sie `RELEASE_TAG` durch deren Tag, `MANIFEST_SHA256` durch den vertrauenswürdigen SHA-256 ihrer `SHA256SUMS` und `INSTALLER_SHA256` durch den SHA-256 ihrer `install.sh`. Bestätigen Sie die Werte unabhängig. Der Installer wird vor dem Start geprüft:

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

Mit `--apply` zeigt der interaktive Installer die Vereinbarung und fragt `[y/N]`; standardmäßig wird abgelehnt. Lesen Sie sie mit `sh install.sh --license`. Eine nichtinteraktive Installation erfordert nach ausdrücklicher Zustimmung `--accept-license`. Im Telefonassistenten ist die separate Zustimmung zunächst nicht markiert.

Bei kompakten Katalogen wird standardmäßig **nur der Hysteria2-Client** im Flash
gespeichert. Wählen Sie bei einem geprüften lokalen Release-Bundle ein Protokoll oder kombinieren Sie Optionen:

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` ist ein Alias für `--wg`. Weitere erkannte Optionen: `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Jedes Modul muss für Firmware und Zielplattform veröffentlicht sein. Bei kompakten Katalogen wählt `--all` alle für die Zielplattform veröffentlichten Client-Protokolle aus. Alle ausgewählten Module müssen denselben Speichermodus unterstützen. Ein ausdrücklich angefordertes fehlendes Protokoll wird abgelehnt. Alte schema-1-Kataloge benötigen eine exakt passende Variante; dort bedeutet `--all` alle erkannten Protokolle.

| Speicher | Verhalten |
| --- | --- |
| `--flash` | Die Engine bleibt nach einem Neustart im Flash. Standard. |
| `--ram` | Die Engine-Binärdatei wird in den RAM geladen und nach einem Neustart bei Bedarf erneut abgerufen. Einstellungen bleiben im Flash. |
| `--auto` | Wählt Flash, wenn das vollständige Budget hineinpasst, sonst einen verfügbaren RAM-Modulsatz. |

Der Speichermodus `--ram` ist vom experimentellen nativen RAM-Bootstrap getrennt. Dauerhafte Bootstrap-Anmeldung bleibt deaktiviert, Kaltstartwiederherstellung ist nicht qualifiziert und die Zulassung des benutzerdefinierten ELF-Bibliothekspfads bleibt ungeklärt. Siehe [RAM-Bootstrap-Einschränkungen](RAM-BOOTSTRAP.md).

Ohne `--apply` wird das ausgewählte Bundle geprüft, aber nicht installiert. Kernelpakete werden nie aktualisiert, um ein inkompatibles Bundle passend zu machen. Bei kompakten Katalogen ist `--server` nur verfügbar, wenn der gewählte Katalog ein kompatibles geprüftes Paket für den eingehenden Hysteria-Server enthält; nur dann wird es ins Ressourcenbudget aufgenommen. Der Server bleibt bis zur Einrichtung des Fernzugriffs ausgeschaltet.

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 Nutzung und Kopplung

Eine PIN-Änderung setzt die Kopplungen zurück: Das Telefon muss erneut verbunden werden; VPN-Profile und Einstellungen bleiben erhalten.

Öffnen Sie **LuCI → Services → FoxHole**, legen Sie eine PIN fest und fügen Sie
ein VPN-Profil hinzu. Regeln leiten Geräte-, Domain- und länderbezogenen Datenverkehr über VPN oder direkt.

`ACCESS_LOCAL_NETWORK` - Router suchen, einrichten und verwalten. Unter Android 17 (API 37) oder neuer fordert die App bei Ziel-API 37 oder neuer vor LAN-Aktionen die Systemberechtigung an. Eine Ablehnung blockiert diese Aktionen.

Die Einrichtung am Telefon sucht am privaten IPv4-Gateway des verbundenen WLANs;
eine Adresse kann auch manuell eingegeben werden. Vor der Kopplung prüft das
Telefon die SSH-Identität und die private LAN-TLS-Identität des Routers. Eine
vorhandene PIN bleibt erhalten. Der Verwaltungsendpunkt bleibt privat.
Das Entkoppeln entfernt den Verwaltungszugriff. Löschen Sie den Remote-Client
separat, um seine VPN-Zugangsdaten zu widerrufen. Beim Entfernen eines alten
gemeinsam genutzten Profils wird nur dessen Eintrag gelöscht; Zugangsdaten eines externen VPN-Anbieters können dadurch nicht widerrufen werden.

Entfernte VPN-Clients benötigen ein separat geprüftes Paket für den eingehenden Hysteria-Server. Es kann mit `--server` nur installiert werden, wenn es im gewählten Release-Katalog enthalten ist. Außerdem sind eine öffentliche WAN-Adresse und ein von außen erreichbarer UDP-Port erforderlich. Dann fügt **VPN-Profil erstellen** einen Remote-Client hinzu; die Auswahl eines vorhandenen Clients öffnet dessen Profil.

Die automatische VPN-Umschaltung im Heimnetz bleibt bis zur tatsächlichen
Routingabnahme einschließlich Fail-Closed- und Zuständigkeitsprüfungen deaktiviert.

In den Android-Apps:

Das WLAN-Symbol zeigt nur eine physische WLAN-Verbindung, ohne SSID oder Standortzugriff. Suche und neue Einrichtung/Kopplung erfordern WLAN. Die manuelle Adresse wird einmal mit dem aktuellen privaten IPv4-WLAN-Gateway vorbelegt, falls verfügbar, und bleibt bearbeitbar.

Über Heim-VPN verwalten ist eine separate Zustimmung und für jede bestehende Kopplung standardmäßig AUS. Zusätzlich sind Ihre Bestätigung Öffentliche IP-Adresse (der Router hat eine öffentliche IP und einen eingehenden VPN-Dienst) und eine nutzbare aktive VPN-Route erforderlich. Diese Bestätigung weist keine Adresse zu und konfiguriert keine Firewall. Die App kann die Verwaltung über dieses VPN-Netz am gespeicherten privaten Endpunkt mit bestehender TLS-Zertifikatsbindung und Kopplungsauthentifizierung versuchen; sie öffnet keinen WAN-Verwaltungsport und ermöglicht keine neue Suche/Kopplung über das Mobilfunknetz.

Separate App-Verknüpfungsmetadaten erhalten nur Profile für den eingehenden VPN-Zugang, die ein authentifizierter gekoppelter Router direkt an die App übergibt. Verbindungs-URI, Konfiguration und QR-Formate bleiben unverändert. Allgemeine Web-/QR-/Provider-Exporte bleiben unmarkiert; importierte Hinweise allein begründen kein Vertrauen.

Die automatische Erkennung erfordert außerdem das passende gespeicherte lokale Profil, dessen aktuelle Konfiguration und die ausgewählte Kopplung, während dieses Profil tatsächlich über das eigene App-VPN verbunden ist. Pro tatsächlicher Verbindung erfolgt eine begrenzte Prüfung, ohne Timer, automatische Wiederholung oder Provider-Profilabfragen. Kopplung wiederholen ist ein ausdrücklicher WLAN-/Berechtigungs-/PIN-Ablauf: Der alte Eintrag bleibt bis zur erfolgreichen Authentifizierung erhalten; eine geänderte Zertifikatsidentität wird nie stillschweigend akzeptiert.

## Einschränkungen

- Länderregeln verwenden IP-Bereiche; Domainregeln hängen vom Router-DNS ab. Sie bestimmen nicht das Land des Websitebetreibers und analysieren keine HTTPS-Inhalte.
- Ein unerwarteter Abbruch der aktiven Core-Verbindung sperrt deren VPN-Routing. Der gesonderte Kill switch steuert die Sperre ohne aktives Profil und ist standardmäßig aus.
- Regelprioritäten, lokale Ausnahmen und Servergrenzen stehen in der [Architektur](ARCHITECTURE.md).

## 🧩 Ein Protokoll später hinzufügen

Wählen Sie unter **Router-VPN → Protokolle** ein verfügbares Protokoll und
bestätigen Sie die Installation. Dieselben Funktionen gibt es in der gekoppelten
Android-App. Jedes Protokoll verwendet ein eigenes kompaktes, signiertes
Engine-Paket; es wird nicht stillschweigend durch eine größere universelle Engine ersetzt.

Beim Hinzufügen eines ungenutzten Protokolls läuft das aktuelle VPN weiter.
Die Aktualisierung des aktiven Protokolls fragt nach einer Neuverbindung.
Beenden Sie die Nutzung eines Protokolls vor dem Entfernen. Angeboten werden nur Pakete für die genaue Zielplattform Ihres Routers.

## ♻️ Aktualisieren und entfernen

### 📥 FoxHole-Paketupdates

Unter **Einstellungen → FoxHole-Update** in Weboberfläche oder gekoppelter App verwenden Prüfung und Installation dieselbe authentifizierte Transaktion. Aktualisiert werden FoxHole-Oberfläche/Runtime und ausgewählte installierte Client-Protokollmodule; ihre FLASH-/RAM-Auswahl bleibt erhalten. Neue Protokolle werden separat installiert. Profile und Kopplung bleiben erhalten; OpenWrt-Firmware und andere Systempakete werden nicht aktualisiert.

Bei direkten CLI-/Backend-Installationen bleiben automatische Updates standardmäßig aus. Bei einer neuen Einrichtung im Web oder unter Android ist ein eigener sichtbarer Schalter für automatische Updates aktiviert; zum Ablehnen deaktivieren Sie ihn. Bestehende Routerrichtlinien einschließlich einer Ablehnung bleiben beim Koppeln und Öffnen der Einrichtung erhalten. Die Richtlinie kann später in den Einstellungen geändert werden.

Bei Aktivierung prüft der Router täglich und installiert verifizierte FoxHole-Paketupdates. Das Entkoppeln des Telefons deaktiviert die Richtlinie nicht. Ältere Pakete ohne Updater benötigen eine separat geprüfte Migration. Siehe [Softwareupdates](UPDATES.md).

Fügen Sie Protokolle über **Router-VPN → Protokolle** am gekoppelten Router oder
Telefon hinzu oder aktualisieren Sie sie dort. Der kompakte Installer dient nur
der Ersteinrichtung. Er bewahrt private Wiederherstellungssicherungen auf und prüft,
dass die DHCP-Einstellungen unverändert bleiben. Nutzen Sie vor dem Löschen von
Paketen bei aktivem Routing die Anleitung zu [Rollback/Entfernung](ROLLBACK.md).
Verwenden Sie geprüfte Release-Pakete. Alte Installer und reine ARM-Downloads werden nicht verwendet. FoxHole Core unterstützt Hysteria2. Bestehende Legacy-Profile verwenden weiterhin die separate Hysteria-Laufzeit und werden nicht automatisch zu Core migriert. Eine aktive Legacy-Hysteria-Verbindung muss vor dem Update manuell beendet werden.

- **Anleitungen:** [CLI](CLI.md) · [Updates](UPDATES.md) · [Rollback](ROLLBACK.md)
- **Architektur:** [Architecture](ARCHITECTURE.md) · [Mobile networks](MOBILE-NETWORKS.md) · [Backup](BACKUP-ARCHITECTURE.md) · [Profile origin](PROFILE-ORIGIN.md)
- **Wartung:** [Release](RELEASE.md) · [Bundle transport](BUNDLE-TRANSPORT.md) · [RAM install](RAM-INSTALL.md) · [Bootstrap](RAM-BOOTSTRAP.md) · [Prerequisites](RAM-PREREQUISITES.md) · [RAM updates](RAM-UPDATE-CONTROLLER.md) · [Engine origin](engine-release-origin.md) · [Security](../SECURITY.md)

## 🤝 Mitwirken

Fehler und Änderungsvorschläge bitte über [Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues) melden.

## 💖 Entwicklung unterstützen

Wir entwickeln und pflegen FoxHole OpenWrt vollständig mit unserer eigenen Zeit und unseren eigenen Mitteln und setzen bei der Entwicklung KI-Werkzeuge ein. Ihre Unterstützung hilft uns, dem Projekt mehr Zeit zu widmen und die Entwicklung zu beschleunigen.

<a id="cryptocurrency-wallets"></a>

### 🪙 Kryptowährungs-Wallets

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

## 📄 Lizenzen

[Lizenz](../LICENSE) · [Hinweise zu Drittanbietern](../THIRD_PARTY_NOTICES.md)
