include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria-server-ram
PKG_VERSION:=2.12.2
PKG_RELEASE:=4
PKG_LICENSE:=MIT
PKG_MAINTAINER:=FoxHole Team
PKG_BUILD_DIR:=$(BUILD_DIR)/hysteria-server-ram-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/hysteria-server-ram
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Exact upstream Hysteria server in volatile storage
  DEPENDS:=@(aarch64||x86_64) +uclient-fetch +ca-bundle +flock +ucode +ucode-mod-fs
  PROVIDES:=hysteria
  CONFLICTS:=hysteria hysteria-ram
endef

define Package/hysteria-server-ram/description
  Dormant incoming Hysteria 2 server, downloaded by exact producer hash
  into root-owned RAM. Runs only after explicit remote-client setup.
endef

define Build/Prepare
	test -n "$(HYSTERIA_PACKAGE_INPUT)" -a -n "$(HYSTERIA_DOWNLOAD_URL)"
	python3 $(CURDIR)/../../tools/check-hysteria-package-input.py \
		--input "$(HYSTERIA_PACKAGE_INPUT)" --architecture "$(ARCH)" \
		--download-url "$(HYSTERIA_DOWNLOAD_URL)" \
		--ram-reserve-bytes "$(HYSTERIA_RAM_RESERVE_BYTES)"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/hysteria-producer.json $(PKG_BUILD_DIR)/
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/*.LICENSE.md $(PKG_BUILD_DIR)/
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/LICENSE.md $(HYSTERIA_PACKAGE_INPUT)/go-modules.json $(HYSTERIA_PACKAGE_INPUT)/GO-THIRD-PARTY-NOTICES.txt \
		$(HYSTERIA_PACKAGE_INPUT)/HYSTERIA-SOURCE-PATCH.patch $(HYSTERIA_PACKAGE_INPUT)/HYSTERIA-PATCH-SOURCE.json $(PKG_BUILD_DIR)/
	python3 -c 'import json,os; p=json.load(open("$(HYSTERIA_PACKAGE_INPUT)/hysteria-producer.json")); print("$(HYSTERIA_DOWNLOAD_URL)"); print(p["binarySha256"]); print(os.stat("$(HYSTERIA_PACKAGE_INPUT)/hysteria").st_size); print("$(HYSTERIA_RAM_RESERVE_BYTES)")' > $(PKG_BUILD_DIR)/hysteria-server-download.txt
endef

define Build/Compile
endef

define Package/hysteria-server-ram/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/foxhole
	$(INSTALL_BIN) ./files/hysteria $(1)/usr/bin/hysteria
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/hysteria-producer.json $(PKG_BUILD_DIR)/hysteria-server-download.txt $(1)/usr/share/foxhole/
	$(INSTALL_DIR) $(1)/usr/share/licenses/hysteria
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.LICENSE.md $(PKG_BUILD_DIR)/LICENSE.md $(PKG_BUILD_DIR)/go-modules.json $(PKG_BUILD_DIR)/GO-THIRD-PARTY-NOTICES.txt \
		$(PKG_BUILD_DIR)/HYSTERIA-SOURCE-PATCH.patch $(PKG_BUILD_DIR)/HYSTERIA-PATCH-SOURCE.json $(1)/usr/share/licenses/hysteria/
endef

$(eval $(call BuildPackage,hysteria-server-ram))
