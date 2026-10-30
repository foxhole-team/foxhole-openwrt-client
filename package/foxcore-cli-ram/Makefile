include $(TOPDIR)/rules.mk

PKG_NAME:=foxcore-cli-ram
PKG_VERSION:=1.0.1
PKG_RELEASE:=2
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=FoxHole Team
PKG_BUILD_DIR:=$(BUILD_DIR)/foxcore-cli-ram-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/foxcore-cli-ram
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FoxCore selectable VPN client in volatile storage
  DEPENDS:=@(aarch64||x86_64) +kmod-tun +ip-full +nftables-json +uclient-fetch +ca-bundle +flock +ucode +ucode-mod-fs
  PROVIDES:=foxcore-cli
  CONFLICTS:=foxcore-cli
endef

define Package/foxcore-cli-ram/description
  Downloads the exact hash-pinned static musl Core producer into private
  volatile storage. Requires Internet access after reboot; no direct fallback.
endef

define Build/Prepare
	test -n "$(FOXCORE_PACKAGE_INPUT)" -a -n "$(FOXCORE_SOURCE_SHA256)"
	test -n "$(FOXCORE_DOWNLOAD_URL)"
	python3 $(CURDIR)/../../tools/check-core-package-input.py \
		--input "$(FOXCORE_PACKAGE_INPUT)" --architecture "$(ARCH)" \
		--version "$(PKG_VERSION)" --source-sha256 "$(FOXCORE_SOURCE_SHA256)" \
		--download-url "$(FOXCORE_DOWNLOAD_URL)" --ram-reserve-bytes "$(FOXCORE_RAM_RESERVE_BYTES)"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(FOXCORE_PACKAGE_INPUT)/core-producer.json $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/LICENSE $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/THIRD_PARTY_NOTICES.md $(PKG_BUILD_DIR)/
	python3 -c 'import json,os; p=json.load(open("$(FOXCORE_PACKAGE_INPUT)/core-producer.json")); print("$(FOXCORE_DOWNLOAD_URL)"); print(p["binarySha256"]); print(os.stat("$(FOXCORE_PACKAGE_INPUT)/foxcore-cli").st_size); print("$(FOXCORE_RAM_RESERVE_BYTES)")' > $(PKG_BUILD_DIR)/core-download.txt
endef

define Build/Compile
endef

define Package/foxcore-cli-ram/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/foxhole
	$(INSTALL_BIN) ./files/foxcore-cli $(1)/usr/bin/foxcore-cli
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core-producer.json $(1)/usr/share/foxhole/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core-download.txt $(1)/usr/share/foxhole/
	$(INSTALL_DIR) $(1)/usr/share/licenses/foxcore-cli
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/foxcore-cli/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/THIRD_PARTY_NOTICES.md $(1)/usr/share/licenses/foxcore-cli/
endef

$(eval $(call BuildPackage,foxcore-cli-ram))
