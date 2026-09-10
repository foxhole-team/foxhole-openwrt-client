# Rollback

Save an OpenWrt backup off-router and retain LAN/console access before
installation. The installer also preserves `sysupgrade-before.tar.gz`,
DHCP and optional FoxHole data in its printed private `/tmp` directory.
Copy these off-router before reboot; `/tmp` is volatile.

1. Stop the services:

   ```sh
   /etc/init.d/foxhole-runtime stop
   /etc/init.d/foxhole-inbound stop
   /etc/init.d/foxhole-history stop
   ```

2. Remove the panel with `apk del foxhole-openwrt-client` while its removal
   hooks exist. Retain an engine required by other packages.
3. Restore a compatible OpenWrt backup through LuCI or
   `sysupgrade -r /tmp/KNOWN_GOOD_BACKUP.tar.gz`.
4. Reinstall previous APKs from a trusted bundle if needed: configuration
   restore does not restore package binaries. Restore FoxHole data only
   into a compatible version.
5. Reboot and verify DHCP, DNS, LAN management, VPN routing and WAN isolation.

Installation is not transactional: failure may leave package changes.
Lost LAN access requires the device's failsafe/console recovery procedure.
