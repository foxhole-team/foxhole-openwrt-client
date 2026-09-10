include $(TOPDIR)/rules.mk

PKG_NAME:=foxhole-openwrt-client
PKG_VERSION:=0.1.0
PKG_RELEASE:=41
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=FoxHole Team

include $(INCLUDE_DIR)/package.mk

define Package/foxhole-openwrt-client
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=FoxHole OpenWrt client panel
  DEPENDS:=+luci-base +rpcd-mod-ucode +ucode-mod-fs \
    +ucode-mod-uci +ucode-mod-ubus +ucode-mod-digest \
    +uclient-fetch +ca-bundle +qrencode +hysteria +kmod-tun \
    +ip-full +nftables-json +firewall4 +jsonfilter +dnsmasq-full
  PKGARCH:=all
endef

define Package/foxhole-openwrt-client/description
  FoxHole OpenWrt management panel and policy-routing runtime for an
  upstream Hysteria 2 client.
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
	/etc/init.d/foxhole-runtime enable
	/etc/init.d/foxhole-runtime restart
	/etc/init.d/foxhole-history enable
	/etc/init.d/foxhole-history restart
	/etc/init.d/foxhole-inbound enable
	/etc/init.d/foxhole-inbound restart
	/etc/init.d/firewall reload
	/etc/init.d/rpcd restart
	/etc/init.d/uhttpd reload
fi
exit 0
endef

define Package/foxhole-openwrt-client/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/foxhole-runtime stop
	/etc/init.d/foxhole-runtime disable
	/etc/init.d/foxhole-history stop
	/etc/init.d/foxhole-history disable
	/etc/init.d/foxhole-inbound stop
	/etc/init.d/foxhole-inbound disable
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
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-runtime \
		$(1)/etc/init.d/foxhole-runtime
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-inbound $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/etc/init.d/foxhole-inbound-services $(1)/etc/init.d/
	$(INSTALL_BIN) ./root/usr/libexec/foxhole-inbound $(1)/usr/libexec/
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
	$(INSTALL_DATA) ./root/usr/share/foxhole/inbound.uc $(1)/usr/share/foxhole/
	$(INSTALL_DATA) ./root/usr/share/foxhole/history.uc $(1)/usr/share/foxhole/
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
	$(INSTALL_DIR) $(1)/usr/share/licenses/foxhole-openwrt-client
	$(INSTALL_DATA) ./licenses/FlagIcons-MIT.txt \
		$(1)/usr/share/licenses/foxhole-openwrt-client/
	$(INSTALL_DATA) ./licenses/TablerIcons-MIT.txt \
		$(1)/usr/share/licenses/foxhole-openwrt-client/
endef

$(eval $(call BuildPackage,foxhole-openwrt-client))
