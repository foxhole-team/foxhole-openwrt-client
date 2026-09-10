<p align="center"><img src="media/logo.png" width="140" alt="FoxHole"></p>

# FoxHole OpenWrt Client

**Public beta 1.0** · [English](#english) · [Русский](#русский)

![FoxHole dashboard](media/dashboard.png)

## English

A Hysteria 2 client and LuCI panel for OpenWrt: supervised TUN, device/site/
country routing, LAN kill switch, optional incoming VPN users and 30-day
history. This is a third-party package, not part of the official OpenWrt feed.

### Install

Current installer target: **OpenWrt 25.12 ARM64 / aarch64_generic (APK)**.
Build or obtain a reviewed release bundle first. Public release artifacts
and signing trust are not published by local repository preparation.

```sh
# Check the bundle and dependency resolution; no package installation.
sh install.sh --bundle /tmp/foxhole-release --manifest-sha256 TRUSTED_SHA256

# Install persistently in FLASH (default).
sh install.sh --bundle /tmp/foxhole-release --manifest-sha256 TRUSTED_SHA256 --apply

# Explicit alternative: store only the Hysteria binary in RAM.
sh install.sh --bundle /tmp/foxhole-release --manifest-sha256 TRUSTED_SHA256 --ram --apply
```

There is **no automatic flash → RAM fallback**. Flash mode requires at
least 32 MiB free overlay and 48 MiB available RAM during preflight. RAM
mode requires 4 MiB overlay and 96 MiB available RAM. These are minimum
installation headroom checks, not throughput guarantees. RAM mode downloads
the checksum-pinned engine again after reboot; settings remain on flash.
Low memory causes refusal, not a forced installation.

`--base-url https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/TAG`
can replace `--bundle` once that signed release exists. Verify the signed
SHA256SUMS through an independently trusted key; supply its SHA-256 as
`TRUSTED_SHA256`. Do not pipe an unverified download into a root shell.
`--development` is only for explicitly approved unsigned test bundles.

### Configure

- Keep web/SSH management LAN-only. The package does not harden an existing
  WAN policy for you. Change the initial `1234` PIN on first login.
- Import a private Hysteria profile through the panel.
  [Examples](examples/) are inactive templates, not working credentials.
- Optional incoming router users default to UDP/443 and need separately
  provisioned TLS and a reachable endpoint. Shared-port users have one LAN
  ACL; per-user LAN access requires separate listener ports.
- Incoming users follow country exceptions through the active VPN when
  client routing is enabled. **When upstream is disconnected, they exit
  directly through the router.** The LAN kill switch is a separate policy.
- Country/domain matching is imperfect: shared addresses and external
  encrypted DNS can bypass domain classification.
- WAN latency measures the gateway; VPN latency measures tunneled HTTPS
  with connection/TLS overhead, not ICMP ping. History collects in the
  background; hourly flash checkpoints may lose the last hour on power loss.

### Build and verify

```sh
npm ci --ignore-scripts
npm run check
npm run build:source
# Linux x86_64, OpenWrt build prerequisites:
sh tools/build-openwrt.sh
```

No frontend npm dependencies are downloaded. The source ZIP and SHA-256 are
deterministic; SDK, feeds, compiler and Hysteria inputs are pinned.
[Build, clean-install test and signed release gates](docs/RELEASE.md)
distinguish local harness tests from real firmware acceptance.
[Rollback](docs/ROLLBACK.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md).

## Русский

Клиент Hysteria 2 и панель LuCI для OpenWrt: TUN, правила устройств,
сайтов и стран, kill switch для LAN, входящие VPN-клиенты и история
за 30 дней. Это сторонний пакет, не официальный пакет репозитория OpenWrt.

### Установка

Установщик рассчитан на **OpenWrt 25.12 ARM64 / aarch64_generic (APK)**.
Команды выше по умолчанию проверяют пакет; `--apply` устанавливает.
**Без флага — всегда flash. Только `--ram` включает хранение бинарника
Hysteria в RAM.** Автоматического переключения нет.

Для flash нужны минимум 32 МиБ свободного overlay и 48 МиБ доступной RAM.
Для RAM-режима — 4 МиБ overlay и 96 МиБ доступной RAM. Это пороги
установки, а не гарантия производительности. Настройки сохраняются во flash,
а бинарник RAM-режима скачивается заново после перезагрузки с проверкой
закреплённой SHA-256. Нехватка оперативной памяти приводит к отказу.

Используйте проверенный пакет и подписанный SHA256SUMS: его хеш передаётся
в `--manifest-sha256`. Подписанные GitHub Releases требуют отдельной
публикации; подготовка исходников их не создаёт. Флаг `--development`
явно отключает проверку подписи APK и предназначен только для тестов.

### Настройка и ограничения

- Web/SSH оставьте доступными только из LAN; существующий WAN-файрвол
  пакет автоматически не закрывает. Начальный PIN `1234` нужно заменить.
- Профиль VPS импортируется в панели. В [examples](examples/) только
  шаблоны; личные ключи, QR, сертификаты и бэкапы храните вне Git.
- Входящие клиенты роутера используют UDP/443, но требуют настройки TLS
  и доступного адреса. На общем порту LAN-ACL общий; отдельный доступ
  в LAN для каждого клиента требует отдельных портов.
- При включённых правилах клиентов используется активный VPN и исключения
  стран. **Без соединения с VPS входящие клиенты выходят напрямую.**
  Kill switch для LAN настраивается отдельно.
- Задержка VPN измеряется запросом HTTPS через туннель, а не ICMP.
  История собирается без открытой панели; при внезапном отключении питания
  может потеряться последний час до сохранения на flash.

[Сборка, чистая установка и выпуск](docs/RELEASE.md) ·
[Откат](docs/ROLLBACK.md) · [Безопасность](SECURITY.md).

Исходный снимок панели оставлен без изменений по запросу владельца.
На нём оставлены видимые подписи адресов; показание CPU
предшествует исправлению расчёта и не является измерением текущей версии.

---

[GitHub](https://github.com/foxhole-team/foxhole-openwrt-client) ·
[GPL-3.0-or-later](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
