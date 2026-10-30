include $(TOPDIR)/rules.mk

PKG_NAME:=foxhole-openwrt-client
PKG_VERSION:=1.0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later GPL-2.0-only Zlib
PKG_MAINTAINER:=FoxHole Team

include $(INCLUDE_DIR)/package.mk

define Package/foxhole-openwrt-client
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=FoxHole OpenWrt client panel
  DEPENDS:=+luci-base +rpcd-mod-ucode +ucode-mod-fs \
    +ucode-mod-uci +ucode-mod-ubus +ucode-mod-digest +ucode-mod-socket \
    +uclient-fetch +ca-bundle +qrencode +kmod-tun \
    +ip-full +nftables-json +firewall4 +jsonfilter +dnsmasq-full \
    +uhttpd +libustream-openssl +openssl-util +flock +libgcc
  PKGARCH:=all
endef

define Package/foxhole-openwrt-client/description
  FoxHole OpenWrt management panel and policy-routing runtime for a
  selectable FoxCore client or separately installed upstream Hysteria 2.
endef

define Package/foxhole-openwrt-client/conffiles
/etc/config/foxhole
/etc/foxhole/
/etc/nftables.d/31-foxhole-inbound.nft
endef

define Build/Compile
endef

define Package/foxhole-openwrt-client/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	if /usr/libexec/foxhole-update-job hooks >/dev/null 2>&1; then exit 0; fi
	/usr/libexec/foxhole-license --show en || exit 1
	printf '%s\n' 'Accept the agreement when setting up FoxHole OpenWRT Client through the web panel, CLI or phone.'
	/etc/init.d/foxhole-runtime enable
	/etc/init.d/foxhole-runtime restart
	/etc/init.d/foxhole-history enable
	/etc/init.d/foxhole-history restart
	/etc/init.d/foxhole-inbound enable
	/etc/init.d/foxhole-inbound restart
	/etc/init.d/foxhole-mobile enable
	/etc/init.d/foxhole-mobile restart
	/etc/init.d/firewall reload
	/etc/init.d/rpcd restart
	/etc/init.d/uhttpd reload
fi
exit 0
endef

define Package/foxhole-openwrt-client/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	if /usr/libexec/foxhole-update-job hooks >/dev/null 2>&1; then exit 0; fi
	/etc/init.d/foxhole-runtime stop
	/etc/init.d/foxhole-runtime disable
	/etc/init.d/foxhole-history stop
	/etc/init.d/foxhole-history disable
	/etc/init.d/foxhole-inbound stop
	/etc/init.d/foxhole-inbound disable
	/etc/init.d/foxhole-mobile stop
	/etc/init.d/foxhole-mobile disable
	nft flush set inet fw4 foxhole_inbound_ports 2>/dev/null
	/usr/libexec/foxhole-runtime cleanup >/dev/null 2>&1
	panel_index='foxhole.html'
	legacy_index='luci-static/resources/foxhole/shell.html'
	old_indexes="$$(uci -q get uhttpd.main.index_page)"
	uci -q delete uhttpd.main.index_page
	for page in $$old_indexes; do
		[ "$$page" = "$$panel_index" ] || \
		[ "$$page" = "$$legacy_index" ] || \
			uci add_list uhttpd.main.index_page="$$page"
	done
	uci commit uhttpd
	/etc/init.d/uhttpd reload
fi
exit 0
endef

define Package/foxhole-openwrt-client/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./root/etc/config/foxhole $(1)/etc/config/foxhole
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/uci-defaults/99-foxhole-openwrt-client \
		$(1)/etc/uci-defaults/99-foxhole-openwrt-client
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-mobile $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-runtime \
		$(1)/etc/init.d/foxhole-runtime
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-update-job ./root/usr/libexec/foxhole-update-hint $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-transaction-stage-v1 ./root/usr/libexec/foxhole-transaction-command-v1 $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-engine-command ./root/usr/libexec/foxhole-engine-command-v2 ./root/usr/libexec/foxhole-engine-fetch ./root/usr/libexec/foxhole-engine-job $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-mobile-listen $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-remote-identity $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-mobile-identity $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-bootstrap-enroll $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-license $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-private-file $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-provider-resolve $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-country-fetch $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-inbound $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-inbound-services $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-inbound $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-inbound-revoke $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-inbound-loop $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-history $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-history $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-history-loop $(1)/usr/libexec/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-runtime \
		$(1)/usr/libexec/foxhole-runtime
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-supervisor \
		$(1)/usr/libexec/foxhole-supervisor
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-dnsmasq \
		$(1)/usr/libexec/foxhole-dnsmasq
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-probe \
		$(1)/usr/libexec/foxhole-probe
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_BIN) ./root/usr/share/rpcd/ucode/foxhole.uc \
		$(1)/usr/share/rpcd/ucode/foxhole.uc
	$(INSTALL_DIR) $(1)/usr/share/foxhole
	$(INSTALL_DATA) ./root/usr/share/foxhole/license-agreement.json $(1)/usr/share/foxhole/
	test -n "$(FOXHOLE_TRANSACTION_MANIFEST_INPUT)" -a -n "$(FOXHOLE_TRANSACTION_MANIFEST_SHA256)"
	test -n "$(FOXHOLE_TRANSACTION_X86_GZIP_INPUT)" -a -n "$(FOXHOLE_TRANSACTION_ARM64_GZIP_INPUT)"
	python3 $(CURDIR)/../../tools/check-transaction-inputs.py \
		--manifest "$(FOXHOLE_TRANSACTION_MANIFEST_INPUT)" \
		--manifest-sha256 "$(FOXHOLE_TRANSACTION_MANIFEST_SHA256)" \
		--x86-gzip "$(FOXHOLE_TRANSACTION_X86_GZIP_INPUT)" \
		--arm64-gzip "$(FOXHOLE_TRANSACTION_ARM64_GZIP_INPUT)" \
		--install-dir "$(1)/usr/share/foxhole"
	$(INSTALL_DATA) ./root/usr/share/foxhole/update-model.uc ./root/usr/share/foxhole/update-native.uc ./root/usr/share/foxhole/update-service.uc ./root/usr/share/foxhole/update-policy.json $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/engine-capture.uc ./root/usr/share/foxhole/engine-package-layout.uc ./root/usr/share/foxhole/engine-model.uc ./root/usr/share/foxhole/engine-registry.uc ./root/usr/share/foxhole/engine-service.uc ./root/usr/share/foxhole/engine-catalog.json $(1)/usr/share/foxhole/
	$(INSTALL_DATA) $(CURDIR)/../../config/foxhole-openwrt-apk.pem $(1)/usr/share/foxhole/
	if [ -n "$(FOXHOLE_ENGINE_CATALOG_INPUT)" ]; then \
		test -n "$(FOXHOLE_ENGINE_CATALOG_SHA256)"; \
		printf '%s  %s\n' "$(FOXHOLE_ENGINE_CATALOG_SHA256)" "$(FOXHOLE_ENGINE_CATALOG_INPUT)" | sha256sum -c -; \
		$(INSTALL_DATA) "$(FOXHOLE_ENGINE_CATALOG_INPUT)" $(1)/usr/share/foxhole/engine-catalog.json; \
	fi
	$(INSTALL_DATA) ./root/usr/share/foxhole/client-observation.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/device-model.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/handoff.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/handoff-adapter.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/remote.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/mobile.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/core-model.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/core-adapter.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/private-store.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/inbound.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/history.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/pairing.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/model.uc \
		$(1)/usr/share/foxhole/model.uc
	$(INSTALL_DATA) ./root/usr/share/foxhole/runtime-model.uc \
		$(1)/usr/share/foxhole/runtime-model.uc
	$(INSTALL_DATA) ./root/usr/share/foxhole/probe.uc \
		$(1)/usr/share/foxhole/probe.uc
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/forward
	$(INSTALL_DATA) ./root/usr/share/nftables.d/chain-pre/forward/30-foxhole.nft \
		$(1)/usr/share/nftables.d/chain-pre/forward/30-foxhole.nft
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/input
	$(INSTALL_DIR) $(1)/etc/nftables.d
	$(INSTALL_DATA) ./root/etc/nftables.d/31-foxhole-inbound.nft $(1)/etc/nftables.d/
	$(INSTALL_DATA) ./root/usr/share/nftables.d/chain-pre/input/31-foxhole-inbound.nft \
		$(1)/usr/share/nftables.d/chain-pre/input/
	$(INSTALL_DATA) ./root/usr/share/nftables.d/chain-pre/input/30-foxhole.nft \
		$(1)/usr/share/nftables.d/chain-pre/input/30-foxhole.nft
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_DIR) $(1)/www/foxhole-mobile/cgi-bin
	$(INSTALL_BIN) ./root/www/cgi-bin/foxhole $(1)/www/foxhole-mobile/cgi-bin/
	$(INSTALL_BIN) ./root/www/cgi-bin/foxhole \
		$(1)/www/cgi-bin/foxhole
	$(INSTALL_DATA) ./htdocs/luci-static/resources/foxhole/shell.html \
		$(1)/www/foxhole.html
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-foxhole.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-foxhole.json
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-foxhole.json \
		$(1)/usr/share/luci/menu.d/luci-app-foxhole.json
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/foxhole
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/foxhole/client.js \
		$(1)/www/luci-static/resources/view/foxhole/client.js
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/foxhole/settings.js \
		$(1)/www/luci-static/resources/view/foxhole/settings.js
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/foxhole/pin.js \
		$(1)/www/luci-static/resources/view/foxhole/pin.js
	$(INSTALL_DIR) $(1)/www/luci-static/resources/foxhole
	$(CP) ./htdocs/luci-static/resources/foxhole/* \
		$(1)/www/luci-static/resources/foxhole/
	find $(1)/www/luci-static/resources/foxhole -type d -exec chmod 755 {} +
	$(INSTALL_DIR) $(1)/usr/share/licenses/foxhole-openwrt-client
	$(INSTALL_DATA) ./licenses/FlagIcons-MIT.txt \
		$(1)/usr/share/licenses/foxhole-openwrt-client/
	$(INSTALL_DATA) ./licenses/TablerIcons-MIT.txt \
		$(1)/usr/share/licenses/foxhole-openwrt-client/
	$(INSTALL_DATA) ./licenses/APK-tools-GPL2.txt ./licenses/MbedTLS-GPL2.txt ./licenses/zlib.txt ./licenses/SOURCE-OFFER.txt \
		$(1)/usr/share/licenses/foxhole-openwrt-client/
endef

$(eval $(call BuildPackage,foxhole-openwrt-client))
