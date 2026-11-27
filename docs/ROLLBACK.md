# Rollback

Save an OpenWrt backup off-router and retain LAN/console access before
installation. The installer also preserves `sysupgrade-before.tar.gz`,
DHCP and optional FoxHole data in its printed private `/tmp` directory.
Copy these off-router before reboot; `/tmp` is volatile.

For package removal, open **Services → FoxHole OpenWRT Client → Uninstall FoxHole** in LuCI, or run this command as root:

```sh
/usr/libexec/foxhole-uninstall
```

The preview identifies the active storage mode and asks for a separate confirmation. On FLASH, only a native transaction that removes the BASE package alone can proceed. On managed RAM, the command disables the recognized FoxHole startup entry. Restart OpenWrt to clear the volatile mounts. Any recovery cache and bootstrap files already on FLASH remain available but their startup entry is disabled. If a FLASH installation remains after reboot, use its removal command. For an older FLASH release without that command, run `apk del --simulate foxhole-openwrt-client` and check that the only package listed for removal is `foxhole-openwrt-client`. Then run `apk del foxhole-openwrt-client`. Preserve the router configuration, private profiles and pairing files when removing the package.

For a full restore to a previous firmware configuration, take the following steps:

1. Stop the services:

   ```sh
   /etc/init.d/foxhole-runtime stop
   /etc/init.d/foxhole-inbound stop
   /etc/init.d/foxhole-history stop
   ```

2. Remove the panel using the storage-specific procedure above.
3. Restore a compatible OpenWrt backup through LuCI or
   `sysupgrade -r /tmp/KNOWN_GOOD_BACKUP.tar.gz`.
4. Reinstall previous APKs from a trusted bundle if needed: configuration
   restore does not restore package binaries. Restore FoxHole data only
   into a compatible version.
5. Reboot and verify DHCP, DNS, LAN management, VPN routing and WAN isolation.

Installation is not transactional: failure may leave package changes.
Lost LAN access requires the device's failsafe/console recovery procedure.
