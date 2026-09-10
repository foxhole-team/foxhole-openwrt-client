# Rollback / Откат

Keep LAN/console access and save an ordinary OpenWrt backup **off-router**
before installation. The installer additionally prints a private staging
directory with `sysupgrade-before.tar.gz`, DHCP and optional FoxHole data.
It is in `/tmp`: reboot erases it. Copy it off-router before rebooting.

1. Stop the installed services:
   `/etc/init.d/foxhole-runtime stop`,
   `/etc/init.d/foxhole-inbound stop`,
   `/etc/init.d/foxhole-history stop`.
2. If removing the package, run `apk del foxhole-openwrt-client` while its
   removal hooks still exist. Do not delete package files manually.
   Retain an engine used by other packages.
3. Restore the ordinary OpenWrt backup through LuCI, or use
   `sysupgrade -r /tmp/KNOWN_GOOD_BACKUP.tar.gz` on the same compatible
   firmware. This restores configuration, not old package binaries.
4. Reinstall the previous pinned APKs from your saved trusted bundle if
   needed. Restore the optional FoxHole data backup separately only when
   returning to a compatible FoxHole version. Never unpack unknown archives.
5. Reboot after saving backups off-router, then check DHCP, DNS, LAN
   access, VPN routes and WAN isolation.

A failed install may already have changed packages; a preserved backup is
recovery material, not an automatic transaction rollback. On loss of LAN
access use the device's OpenWrt failsafe/console recovery procedure.

## Русский

Сначала сохраните штатный бэкап OpenWrt **на другом устройстве**.
Дополнительный бэкап установщика находится в `/tmp` и пропадёт при ребуте.

Остановите три службы выше; при удалении используйте пакетный менеджер,
чтобы выполнились штатные обработчики очистки. Восстановите совместимый
бэкап через LuCI или `sysupgrade -r`. Он возвращает настройки, но не
предыдущие APK: их при необходимости переустановите из доверенного бандла.
Перезагрузите роутер и проверьте сеть. При недоступной LAN нужен failsafe
или консоль. Автоматический откат при ошибке установки не гарантируется.
