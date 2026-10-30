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

VPN-Profile, Routingregeln und eine einfache Oberfläche für OpenWrt-Router.
Ausgehende VPN-Verbindungen nutzen [FoxCore](https://github.com/foxhole-team/foxhole-core).
Kompakte Installationen verwenden für jedes ausgewählte Protokoll ein eigenes
Clientmodul. Ein optionaler Hysteria-Server nimmt Verbindungen Ihrer Geräte an.

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

## 🔌 Unterstützte VPN-Protokolle

Aktuelle FoxHole-VPN-Module für den Router:

| Protokoll | Installationsoption |
| --- | --- |
| VLESS | `--vless` |
| Hysteria2 | `--hy2` |
| WireGuard | `--wg` |

## 📋 Voraussetzungen

- OpenWrt 25.12.5 mit APK, Root-Zugriff und Internetverbindung.
- Veröffentlichte Pakete für die genaue Firmware, Zielplattform, Architektur und ausgewählten Protokolle. Die aktuelle Paket-/Updaterichtlinie lässt `x86/64` und `mediatek/filogic` zu; ein SDK-Build oder ARM-Architekturname bestätigt nicht jedes Routermodell.
- Genügend Flash und RAM für das vollständige geprüfte Paketbudget. Vor Paketänderungen prüft der Installer Abhängigkeiten, Kernel-ABI und Zwischenspeicherplatz.
- Zugriff aus einem vertrauenswürdigen LAN. Aktivieren Sie zuerst WLAN, falls es auf einem neuen Router deaktiviert ist.

In dieser öffentlichen Beta verwenden die ausgehenden VPN-Module FoxHole Core 1.0.1. Unterstützung im Quellcode und eine kreuzkompilierte Binärdatei
allein belegen keine Routerkompatibilität. Installierbar sind nur Pakete aus
einem authentifizierten Release-Katalog. Beim eingehenden Server bestehen zwei
geprüfte Abhängigkeitsbefunde in ungenutzten S2/OpenPGP-Paketen; Prüfungen für den
exakten Build und die Gültigkeitsfrist stehen unter [Release](RELEASE.md).

## 📦 Installation

Verwenden Sie einen veröffentlichten, geprüften Release-Tag und den unabhängig
authentifizierten SHA-256-Wert seiner `SHA256SUMS`. Dieser Befehl prüft den Installer vor der Ausführung:

```sh
(set -eu; url='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/RELEASE_TAG'; f=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$f"' EXIT; uclient-fetch -q -T 60 -O "$f" "$url/install.sh"; printf '%s  %s\n' 'fb0a2bad91a1eebd3591801f79dd6b83fc70bf94ddc1b8d6577f94519de1d1d9' "$f" | sha256sum -c -; sh "$f" --base-url "$url" --manifest-sha256 MANIFEST_SHA256 --apply)
```

Mit `--apply` zeigt der interaktive Installer die Vereinbarung und fragt `[y/N]`; standardmäßig wird abgelehnt. Lesen Sie sie mit `sh install.sh --license`. Eine nichtinteraktive Installation erfordert nach ausdrücklicher Zustimmung `--accept-license`. Im Telefonassistenten ist die separate Zustimmung zunächst nicht markiert.

Bei kompakten Katalogen wird standardmäßig **nur der Hysteria2-Client** im Flash
gespeichert. Wählen Sie bei einem geprüften lokalen Release-Bundle ein Protokoll oder kombinieren Sie Optionen:

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --server --ram --apply
```

`-wg` ist ein Alias für `--wg`. Weitere erkannte Optionen: `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Kompakte Kataloge kombinieren veröffentlichte Module in einem gemeinsamen
Speichermodus. Jedes ausgewählte Modul muss für Ihre Firmware und Zielplattform
verfügbar sein. `--all` fordert alle erkannten Protokolle an und wird abgelehnt,
wenn ein Modul fehlt. Alte Kataloge mit schema 1 erfordern eine genau passende Variante.

| Speicher | Verhalten |
| --- | --- |
| `--flash` | Die Engine bleibt nach einem Neustart im Flash. Standard. |
| `--ram` | Die Engine verwendet RAM und lädt nach einem Neustart die festgelegte Binärdatei herunter. Einstellungen bleiben im Flash. |
| `--auto` | Wählt Flash, wenn das vollständige Budget hineinpasst, sonst einen verfügbaren RAM-Modulsatz. |

Ohne `--apply` wird das ausgewählte Bundle geprüft, aber nicht installiert.
Kernelpakete werden niemals aktualisiert, um ein inkompatibles Bundle passend
zu machen. In kompakten Katalogen ergänzt `--server` den eingehenden Hysteria-Server
im Ressourcenbudget. Er bleibt ausgeschaltet, bis der Fernzugriff eingerichtet ist.

## 🔗 Nutzung und Kopplung

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
Verwenden Sie geprüfte Release-Pakete. Historische alte Installer und reine
ARM-Downloads sind ausgeschlossen; bestehende HY2-Profile werden weiterhin von Core unterstützt.

[Befehle](CLI.md) · [Architektur](ARCHITECTURE.md) ·
[Build und Release](RELEASE.md) · [Sicherheit](../SECURITY.md)

## 💖 Entwicklung unterstützen

Wir entwickeln und pflegen FoxHole OpenWrt vollständig mit unserer eigenen Zeit und unseren eigenen Mitteln, unterstützt durch KI-Werkzeuge. Ihre Unterstützung hilft uns, dem Projekt mehr Zeit zu widmen und die Entwicklung zu beschleunigen.

[Projekt unterstützen - Kryptowährungs-Wallets](#cryptocurrency-wallets)

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
