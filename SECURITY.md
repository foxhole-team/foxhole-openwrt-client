# Security policy

This is a public-beta third-party OpenWrt package. It requires router
administrator privileges. Keep the web panel and SSH on trusted LANs;
the package does not replace auditing your WAN firewall. The short panel
PIN is not a substitute for router authentication or LAN isolation.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/foxhole-team/foxhole-openwrt-client/security/advisories/new)
when enabled. If unavailable, ask maintainers for a private reporting
channel without posting exploit details publicly. Include the affected
commit/OpenWrt version and redacted reproduction steps.

Do not submit real profiles, keys, QR exports, certificates, backups or
unredacted logs. Templates and reserved test networks are intentional.
The dashboard screenshot is retained as supplied at the owner's request.

- Default install uses flash; only `--ram` selects volatile binary storage.
- Artifact integrity requires a separately authenticated SHA-256 manifest;
  production APKs also need a trusted signing key. `--development` bypasses
  APK signature verification for explicit testing only.
- The initial PIN must be replaced before normal panel operations.
- Incoming VPN users deliberately fall back to direct egress when upstream
  is disconnected; this differs from the LAN kill switch.
- Shared UDP/443 has one listener ACL, not independent per-user LAN ACLs.
- RAM startup needs upstream HTTPS download availability.
- If credentials leak, revoke/rotate them; deleting a Git file is not enough.

## Русский

Не публикуйте профили, ключи, QR, сертификаты, бэкапы и неочищенные логи.
Сообщайте об уязвимостях приватно. Панель и SSH должны оставаться в LAN.
При утечке отзовите и замените секреты. Прямая маршрутизация входящих
клиентов при отключённом VPS — предусмотренное поведение, не kill switch.
