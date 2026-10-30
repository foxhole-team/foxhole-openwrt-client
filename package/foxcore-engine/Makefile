include $(TOPDIR)/rules.mk

FOXCORE_ENGINE_ID?=hysteria2
FOXCORE_ENGINE_STORAGE?=FLASH
FOXCORE_ENGINE_PACKAGE_ARCH?=$(ARCH_PACKAGES)
FOXCORE_ENGINE_MANIFEST_SHA256?=unconfigured
PKG_NAME:=foxcore-engine-$(FOXCORE_ENGINE_ID)-$(if $(filter RAM,$(FOXCORE_ENGINE_STORAGE)),ram,flash)-$(FOXCORE_ENGINE_MANIFEST_SHA256)
PKG_VERSION:=1.0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=FoxHole Team
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
RSTRIP:=:

define Package/$(PKG_NAME)
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FoxCore immutable $(FOXCORE_ENGINE_ID) engine
  DEPENDS:=@(aarch64||x86_64)
endef

define Package/$(PKG_NAME)/description
  One verified protocol producer in a versioned immutable slot.
  It has no init scripts, service hooks or replacement of another engine.
endef

define Build/Prepare
	test -n "$(FOXCORE_PACKAGE_INPUT)" -a -n "$(FOXCORE_SOURCE_SHA256)"
	test "$(FOXCORE_ENGINE_MANIFEST_SHA256)" != unconfigured
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	python3 $(CURDIR)/../../tools/check-engine-package-input.py \
		--input "$(FOXCORE_PACKAGE_INPUT)" --id "$(FOXCORE_ENGINE_ID)" \
		--storage "$(FOXCORE_ENGINE_STORAGE)" --architecture "$(ARCH)" \
		--package-architecture "$(FOXCORE_ENGINE_PACKAGE_ARCH)" --version "$(PKG_VERSION)" \
		--source-sha256 "$(FOXCORE_SOURCE_SHA256)" \
		--legal-input "$(FOXCORE_ENGINE_LEGAL_INPUT)" \
		--legal-provenance-sha256 "$(FOXCORE_ENGINE_LEGAL_PROVENANCE_SHA256)" \
		--memory-bytes "$(FOXCORE_RUNTIME_MEMORY_BYTES)" \
		--reserve-bytes "$(FOXCORE_RAM_RESERVE_BYTES)" \
		$(if $(filter RAM,$(FOXCORE_ENGINE_STORAGE)),--launcher "$(CURDIR)/files/foxcore-engine-ram",) \
		--manifest-sha256 "$(FOXCORE_ENGINE_MANIFEST_SHA256)" --output "$(PKG_BUILD_DIR)/slot.json"
	$(CP) $(FOXCORE_PACKAGE_INPUT)/core-producer.json $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/capabilities.json $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/LICENSE $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_PACKAGE_INPUT)/THIRD_PARTY_NOTICES.md $(PKG_BUILD_DIR)/
	$(CP) $(FOXCORE_ENGINE_LEGAL_INPUT)/DEPENDENCY-LICENSES.txt $(FOXCORE_ENGINE_LEGAL_INPUT)/RUNTIME-NOTICES.txt $(FOXCORE_ENGINE_LEGAL_INPUT)/LEGAL-PROVENANCE.json $(PKG_BUILD_DIR)/
	$(if $(filter RAM,$(FOXCORE_ENGINE_STORAGE)), \
		$(CP) ./files/foxcore-engine-ram $(PKG_BUILD_DIR)/foxcore-cli, \
		$(CP) $(FOXCORE_PACKAGE_INPUT)/foxcore-cli $(PKG_BUILD_DIR)/foxcore-cli)
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/libexec/foxhole/engines/$(FOXCORE_ENGINE_ID)/$(FOXCORE_ENGINE_MANIFEST_SHA256)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/foxcore-cli $(1)/usr/libexec/foxhole/engines/$(FOXCORE_ENGINE_ID)/$(FOXCORE_ENGINE_MANIFEST_SHA256)/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/slot.json $(PKG_BUILD_DIR)/core-producer.json $(PKG_BUILD_DIR)/capabilities.json \
		$(1)/usr/libexec/foxhole/engines/$(FOXCORE_ENGINE_ID)/$(FOXCORE_ENGINE_MANIFEST_SHA256)/
	$(INSTALL_DIR) $(1)/usr/share/licenses/$(PKG_NAME)
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(PKG_BUILD_DIR)/THIRD_PARTY_NOTICES.md \
		$(PKG_BUILD_DIR)/DEPENDENCY-LICENSES.txt $(PKG_BUILD_DIR)/RUNTIME-NOTICES.txt $(PKG_BUILD_DIR)/LEGAL-PROVENANCE.json $(1)/usr/share/licenses/$(PKG_NAME)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

# These exact engine packages must not inherit SDK service hooks.
APK_SCRIPTS_$(PKG_NAME):=
Package/$(PKG_NAME)/PROVIDES:=
