include $(TOPDIR)/rules.mk

PKG_NAME:=foxcore-cli
PKG_VERSION:=1.0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=FoxHole Team
PKG_BUILD_DIR:=$(BUILD_DIR)/foxcore-cli-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

# Keep the verified native producer bytes unchanged.
RSTRIP:=:

define Package/foxcore-cli
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FoxCore selectable VPN client runtime
  DEPENDS:=@(aarch64||x86_64) +kmod-tun +ip-full +nftables-json
endef

define Package/foxcore-cli/description
  Linux VPN client with compiled protocol selection, owned TUN,
  authenticated loopback relay and VPN-bound connection proof.
  HY2 server support remains a separate Hysteria package.
endef

define Build/Prepare
	test -n "$(FOXCORE_PACKAGE_INPUT)" -a -n "$(FOXCORE_SOURCE_SHA256)"
	python3 $(CURDIR)/../../tools/check-core-package-input.py \
		--input "$(FOXCORE_PACKAGE_INPUT)" \
		--architecture "$(ARCH)" --version "$(PKG_VERSION)" \
		--source-sha256 "$(FOXCORE_SOURCE_SHA256)"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(FOXCORE_PACKAGE_INPUT)/foxcore-cli $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/core-producer.json $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/LICENSE $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/THIRD_PARTY_NOTICES.md $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/foxcore-cli/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/foxhole
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/foxcore-cli $(1)/usr/bin/foxcore-cli
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core-producer.json $(1)/usr/share/foxhole/
	$(INSTALL_DIR) $(1)/usr/share/licenses/foxcore-cli
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/foxcore-cli/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/THIRD_PARTY_NOTICES.md $(1)/usr/share/licenses/foxcore-cli/
endef

$(eval $(call BuildPackage,foxcore-cli))
