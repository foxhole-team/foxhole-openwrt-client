<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

VPN-Profile, Routingregeln und eine einfache Oberfläche für OpenWrt-Router.
Ausgehende VPN-Verbindungen nutzen [FoxHole Core](https://github.com/foxhole-team/foxhole-core).
Kompakte Installationen verwenden ein eigenes Clientmodul je ausgewähltem Protokoll. Der eingehende Hysteria-Server wird separat bereitgestellt und gehört nicht zum veröffentlichten Clientpaket v1.0.1.

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

<p align="center"><a href="#quickstart">Einstieg</a> · <a href="#features">Funktionen</a> · <a href="#details">Details</a> · <a href="#whats-new">Was ist neu</a></p>

<a id="whats-new"></a>

> **🆕 Was ist neu - 1.0.3 Beta**
>
> - Den API-Zugriff aus dem lokalen Netzwerk und die Weboberfläche korrigiert.
> - Diagramme und die Anzeige der Einstellungen korrigiert.
> - Sichern und Wiederherstellen von Einstellungen, VPN-Profilen und Clients hinzugefügt.
> - Eine Übersicht gekoppelter Mobilgeräte hinzugefügt.
> - Die PIN auf sechs Ziffern erweitert und Sperren nach falschen Eingaben hinzugefügt. Die PIN kann über LuCI geändert werden.
> - Kopplung mit bis zu 10 Mobilgeräten wird unterstützt.
> - Die Prüfung von GitHub-Release-Daten korrigiert.
> - Benachrichtigungen, Bestätigungsdialoge, Hilfe und Hinweise überarbeitet.
> - Prüfung des standardmäßigen Zertifikats-Symlinks bei der Vorbereitung der RAM-Paketwiederherstellung korrigiert.
> - Den Exit-Code des VPN-Prozesses zur Diagnose von Verbindungsabbrüchen hinzugefügt.
> - Links zu VPN-Modulen für Updates des OpenWrt-Clients korrigiert.

<a id="features"></a>

## 🔌 Unterstützte VPN-Protokolle

Aktuelle FoxHole-VPN-Module für den Router:

| Protokoll | Installationsoption | Beschreibung |
| --- | --- | --- |
| VLESS | `--vless` | Proxyverbindung zu einem kompatiblen VLESS-Server mit den Parametern des VPN-Profils. |
| Hysteria2 | `--hy2` | Verbindung zu einem Hysteria2-Server über QUIC/UDP mit einem eigenen Clientmodul. |
| WireGuard | `--wg` | IP-Tunnel auf Schicht 3 zu einem WireGuard-Peer; das Profil legt Schlüssel, Adressen und Netzparameter fest. |

## 📋 Voraussetzungen

- OpenWrt 25.12.5 mit Paketmanager apk und Root-Zugriff. Direkte Downloads benötigen Internet am Router; ein lokales `--bundle` benötigt nur ein vertrauenswürdiges LAN.
- Veröffentlichte Pakete für die genaue Firmware, Zielplattform, Architektur und ausgewählten Protokolle. Die aktuelle Paket-/Updaterichtlinie lässt `x86/64` und `mediatek/filogic` zu; ein SDK-Build oder ARM-Architekturname bestätigt nicht jedes Routermodell.
- Genügend Flash und RAM für das vollständige geprüfte Paketbudget. Vor Paketänderungen prüft der Installer Abhängigkeiten, Kernel-ABI und Zwischenspeicherplatz.
- Zugriff aus einem vertrauenswürdigen lokalen Netz. Für Suche und Ersteinrichtung unter Android das Telefon mit dem WLAN des Routers verbinden.

In dieser öffentlichen Beta verwenden die ausgehenden VPN-Module FoxHole Core 1.0.2. Unterstützung im Quellcode und eine kreuzkompilierte Binärdatei
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
| `--ram` | Die Engine verwendet RAM und lädt nach einem Neustart die festgelegte Binärdatei herunter. Einstellungen bleiben im Flash. |
| `--auto` | Wählt Flash, wenn das vollständige Budget hineinpasst, sonst einen verfügbaren RAM-Modulsatz. |

Ohne `--apply` wird das ausgewählte Bundle geprüft, aber nicht installiert.
Kernelpakete werden niemals aktualisiert, um ein inkompatibles Bundle passend
zu machen. In kompakten Katalogen ergänzt `--server` den eingehenden Hysteria-Server
im Ressourcenbudget. Er bleibt ausgeschaltet, bis der Fernzugriff eingerichtet ist.

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

Das veröffentlichte Clientpaket v1.0.1 enthält keinen eingehenden Hysteria-Server. Entfernte VPN-Clients benötigen ein separat geprüftes Serverpaket; `--server` ist nur mit einem Katalog verfügbar, der es enthält. Außerdem sind eine öffentliche WAN-Adresse und ein von außen erreichbarer UDP-Port nötig.

Für den Fernzugriff ist der mit `--server` ausgewählte Hysteria-Server erforderlich.
Auf einem Router mit öffentlicher WAN-Adresse fügt **VPN-Profil erstellen** einen
Remote-Client hinzu. Bei Auswahl eines Clients öffnet sich dessen vorhandenes Profil.
Der UDP-Listener muss auch von außerhalb Ihres Heimnetzes erreichbar sein.
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

Direkte CLI-/Backend-Installationen lassen automatische Updates standardmäßig aus. Bei einer neuen Einrichtung am Telefon ist das separate sichtbare Updatekästchen aktiviert; deaktivieren Sie es bei Bedarf. Die gewählte Richtlinie wird nach Installation und Kopplung gespeichert. Die Kopplung eines vorhandenen Routers behält dessen Richtlinie bei; später kann sie in den Einstellungen geändert werden.

Bei Aktivierung prüft der Router täglich und installiert verifizierte FoxHole-Paketupdates. Das Entkoppeln des Telefons deaktiviert die Richtlinie nicht. Ältere Pakete ohne Updater benötigen eine separat geprüfte Migration. Siehe [Softwareupdates](UPDATES.md).

Fügen Sie Protokolle über **Router-VPN → Protokolle** am gekoppelten Router oder
Telefon hinzu oder aktualisieren Sie sie dort. Der kompakte Installer dient nur
der Ersteinrichtung. Er bewahrt private Wiederherstellungssicherungen auf und prüft,
dass die DHCP-Einstellungen unverändert bleiben. Nutzen Sie vor dem Löschen von
Paketen bei aktivem Routing die Anleitung zu [Rollback/Entfernung](ROLLBACK.md).
Verwenden Sie geprüfte Release-Pakete. Alte Installer und reine ARM-Downloads werden nicht verwendet. FoxHole Core unterstützt Hysteria2. Bestehende Legacy-Profile verwenden weiterhin die separate Hysteria-Laufzeit und werden nicht automatisch zu Core migriert. Eine aktive Legacy-Hysteria-Verbindung muss vor dem Update manuell beendet werden.

[Befehle](CLI.md) · [Architektur](ARCHITECTURE.md) ·
[Build und Release](RELEASE.md) · [Sicherheit](../SECURITY.md)

<a id="ecosystem"></a>

## 🔗 FoxHole-Ökosystem

| Projekt | Aufgabe |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, Verkehrsregeln und lokale Überwachung |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: einfacher VPN-Client und gekoppelte OpenWrt-Verwaltung |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | Gemeinsamer Rust-Netzwerkkern; Umfang je Build |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | Router-VPN und Verwaltung des lokalen Netzes |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Signierte Regeln und Referenzdaten |

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
