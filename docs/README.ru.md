<p align="center">
  <img src="../media/fhg.gif" alt="FoxHole OpenWrt Client" width="180" height="180">
</p>

<p align="center">
  <a href="../README.md"><img src="https://img.shields.io/badge/🇬🇧-English-ff7a00?style=flat-square" alt="English"></a>
  <a href="README.ru.md"><img src="https://img.shields.io/badge/🇷🇺-Русский-ff7a00?style=flat-square" alt="Русский"></a>
</p>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases"><img src="https://img.shields.io/badge/status-public_beta_1.0-ff7a00?style=flat-square" alt="Public beta 1.0"></a>
</p>

# FoxHole OpenWrt Client

![Platform](https://img.shields.io/badge/platform-OpenWrt-00B5E2?style=flat-square&logo=openwrt&logoColor=white)
![Engine](https://img.shields.io/badge/engine-Hysteria_2-555?style=flat-square)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-007ec6?style=flat-square)](../LICENSE)

**FoxHole OpenWrt Client** объединяет туннель Hysteria 2, правила
маршрутизации и панель LuCI для маршрутизаторов OpenWrt. Использует движок
Hysteria независимо от FoxHole Core и FoxHole DB. Это пока прототип в разработке.

## Возможности

| Компонент | Назначение |
| --- | --- |
| Туннель | Hysteria 2 TUN под контролем службы; импорт профилей URI и JSON. |
| Маршрутизация | Правила устройств, доменов и стран; прямой/VPN-маршрут и kill switch для LAN. |
| Входящий VPN | Необязательные слушатели Hysteria с учётными данными и правилами доступа в LAN. |
| Мониторинг | Трафик, CPU, RAM, задержка WAN/VPN и локальная история за 30 дней. |
| Интерфейс | LuCI и отдельная панель; английский и русский языки. |

![Панель FoxHole](../media/dashboard.png)

Сохранённый снимок сделан до исправления расчёта CPU; его показания
не являются измерениями текущей сборки.

## Установка

Целевая система: **OpenWrt 25.12.x, ARM64, `aarch64_generic`, APK**.
Запуск от root через LAN; нужны HTTPS-загрузки. Установщик проверяет
закреплённый публичный ключ FoxHole и добавляет его перед установкой пакетов.

Установка из GitHub одной командой **после публикации подписанного выпуска**:
замените `RELEASE_TAG` на проверенный тег, а `MANIFEST_SHA256` — на SHA-256
его `SHA256SUMS`, подлинность которого подтверждена независимым способом.
Встроенный хеш проверяет установщик до запуска; хеши APK берутся из манифеста.
Для публичного ключа отдельно закреплён SHA-256. Подпись каждого APK
проверяется до установки; отключать проверку доверия не требуется.

```sh
(set -eu; url='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/RELEASE_TAG'; f=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$f"' EXIT; uclient-fetch -q -T 60 -O "$f" "$url/install.sh"; printf '%s  %s\n' '0ef98c75377112087ef1c33e4cf5ec1521300bf3d0b9cf39bddff2238a9d6bf8' "$f" | sha256sum -c -; sh "$f" --base-url "$url" --manifest-sha256 MANIFEST_SHA256 --apply)
```

| Хранение | Свободный overlay | Доступная RAM | После перезагрузки |
| --- | ---: | ---: | --- |
| Flash, по умолчанию | 32 МиБ | 48 МиБ | Движок сохраняется. |
| `--ram` | 4 МиБ | 96 МиБ | Движок скачивается заново с проверкой закреплённого хеша. |

Это пороги установки. Настройки в обоих режимах остаются во flash;
автоматического переключения нет. Уберите `--apply` для проверки:
обновятся индексы APK и проверятся зависимости, пакеты установлены не будут.
См. [команды CLI](CLI.md), [процедуру выпуска](RELEASE.md) и [откат](ROLLBACK.md).

## Работа и ограничения

Откройте **LuCI → Services → FoxHole**, замените начальный PIN `1234`
и импортируйте профиль сервера. Установка также назначает панель главной
веб-страницей. Web/SSH должны быть доступны из доверенных LAN.
[Примеры конфигурации](../examples/) содержат неактивные шаблоны.

- Для входящих пользователей нужны TLS и доступный UDP-адрес.
  Общий UDP/443 использует один LAN ACL; отдельные ACL требуют разных портов.
  **Без соединения с вышестоящим VPN входящие пользователи выходят напрямую.**
  Kill switch для LAN настраивается отдельно.
- Классификация доменов зависит от наблюдаемого DNS; шифрованный DNS
  и общие IP-адреса ограничивают точность. Задержка WAN измеряется до шлюза,
  VPN — HTTPS-запросом через туннель, включая установление соединения.
- История собирается без открытой панели. При потере питания может
  пропасть до часа данных между сохранениями во flash.

## Разработка и CI

Node 22+, Python 3.11+ и Gitleaks 8.30.1:

```sh
npm ci --ignore-scripts
npm run check
npm run build:source
```

Frontend не требует npm-зависимостей. GitHub Actions проверяет изменения
на push/PR и собирает неподписанные APK после успешных проверок `dev`.
Подписанный `main` принимает успешный кандидат `dev` с теми же исходниками.
`main` автоматически готовит черновик выпуска. Пакетные подписи и GPG-подпись
владельца создаются локально. См. [проверки, сборку и выпуск](RELEASE.md),
[CLI](CLI.md) и [архитектуру с двумя схемами](ARCHITECTURE.md).

---

[Безопасность](../SECURITY.md) · [Изменения](../CHANGELOG.md) · [Сторонние компоненты](../THIRD_PARTY_NOTICES.md)

FoxHole: [Android](https://github.com/foxhole-team/foxhole-guard) ·
[Core](https://github.com/foxhole-team/foxhole-core) ·
[Data](https://github.com/foxhole-team/foxhole-db)
