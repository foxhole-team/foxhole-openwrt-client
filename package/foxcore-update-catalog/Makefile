include $(TOPDIR)/rules.mk

FOXCORE_UPDATE_VERSION?=unconfigured
PKG_NAME:=foxcore-update-catalog
PKG_VERSION:=$(FOXCORE_UPDATE_VERSION)
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=FoxHole Team
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/foxcore-update-catalog
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Signed independent FoxCore update catalog
  PKGARCH:=all
endef

define Package/foxcore-update-catalog/description
  Bounded metadata for verified single-protocol Core packages.
  The router verifies this archive without installing its payload.
endef

define Build/Prepare
	test "$(FOXCORE_UPDATE_VERSION)" != unconfigured
	test -n "$(FOXCORE_UPDATE_INPUT)" -a -n "$(FOXCORE_UPDATE_PAYLOAD_SHA256)"
	test -n "$(FOXCORE_UPDATE_SEQUENCE)" -a -n "$(FOXCORE_UPDATE_MINIMUM_BASE)"
	test -n "$(FOXCORE_UPDATE_PUBLISHED_MS)" -a -n "$(FOXCORE_UPDATE_EXPIRES_MS)"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	python3 $(CURDIR)/../../tools/build-core-update-catalog.py \
		--input "$(FOXCORE_UPDATE_INPUT)" --version "$(PKG_VERSION)" \
		--sequence "$(FOXCORE_UPDATE_SEQUENCE)" \
		--minimum-base-version "$(FOXCORE_UPDATE_MINIMUM_BASE)" \
		--published-at-unix-ms "$(FOXCORE_UPDATE_PUBLISHED_MS)" \
		--expires-at-unix-ms "$(FOXCORE_UPDATE_EXPIRES_MS)" \
		--expected-sha256 "$(FOXCORE_UPDATE_PAYLOAD_SHA256)" \
		--output "$(PKG_BUILD_DIR)/core-update.json"
endef

define Build/Compile
endef

define Package/foxcore-update-catalog/install
	$(INSTALL_DIR) $(1)/usr/share/foxhole-core-catalog
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core-update.json $(1)/usr/share/foxhole-core-catalog/
endef

$(eval $(call BuildPackage,foxcore-update-catalog))
APK_SCRIPTS_foxcore-update-catalog:=
Package/foxcore-update-catalog/PROVIDES:=
