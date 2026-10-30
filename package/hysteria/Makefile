include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria
PKG_VERSION:=2.12.2
PKG_RELEASE:=5
PKG_SOURCE:=hysteria-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/apernet/hysteria/tar.gz/app/v$(PKG_VERSION)?
PKG_HASH:=8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e
PKG_SOURCE_SUBDIR:=hysteria-app-v$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DEPENDS:=$(if $(HYSTERIA_PACKAGE_INPUT),,$(if $(FOXHOLE_GO),,golang/host))
PKG_BUILD_PARALLEL:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE.md app/LICENSE.md core/LICENSE.md extras/LICENSE.md
PKG_MAINTAINER:=FoxHole Team

include $(INCLUDE_DIR)/package.mk
ifeq ($(HYSTERIA_PACKAGE_INPUT),)
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk
endif
RSTRIP:=:

FOXHOLE_GO?=$(STAGING_DIR_HOSTPKG)/lib/go-cross/bin/go
HYSTERIA_COMMIT:=619a6f856b69fb7ee6a7a379e810e68b84004605
HYSTERIA_QUIC:=v0.61.1-0.20260806010916-184d081eef3e
HYSTERIA_DATE:=2026-09-08
ifeq ($(HYSTERIA_PACKAGE_INPUT),)
HYSTERIA_TOOLCHAIN:=$(shell $(FOXHOLE_GO) env GOVERSION 2>/dev/null)
endif

define Package/hysteria
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Hysteria 2 legacy client and optional incoming server
  URL:=https://github.com/apernet/hysteria
endef

define Package/hysteria/description
  Hysteria 2 with the pinned network dependency security repair for legacy client profiles
  and optional incoming server listeners; independent of Core outbound.
endef

define Build/Configure
endef

ifneq ($(HYSTERIA_PACKAGE_INPUT),)
define Build/Prepare
	python3 $(CURDIR)/../../tools/check-hysteria-package-input.py \
		--input "$(HYSTERIA_PACKAGE_INPUT)" --architecture "$(ARCH)"
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/hysteria $(PKG_BUILD_DIR)/
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/hysteria-producer.json $(PKG_BUILD_DIR)/
	$(CP) $(HYSTERIA_PACKAGE_INPUT)/LICENSE.md $(HYSTERIA_PACKAGE_INPUT)/*.LICENSE.md \
		$(HYSTERIA_PACKAGE_INPUT)/go-modules.json $(HYSTERIA_PACKAGE_INPUT)/GO-THIRD-PARTY-NOTICES.txt \
		$(HYSTERIA_PACKAGE_INPUT)/HYSTERIA-SOURCE-PATCH.patch $(HYSTERIA_PACKAGE_INPUT)/HYSTERIA-PATCH-SOURCE.json $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef
else
define Build/Compile
	@test -n "$(HYSTERIA_TEST_SUITE_INPUT)" || { echo "Verified fresh Hysteria test suite required" >&2; exit 1; }
	cd $(PKG_BUILD_DIR) && $(GO_PKG_VARS) CGO_ENABLED=0 \
		$(FOXHOLE_GO) build \
			-mod=readonly -trimpath -buildvcs=false \
			-ldflags "-s -w -buildid= \
			-X github.com/apernet/hysteria/app/v2/cmd.appVersion=$(PKG_VERSION) \
			-X github.com/apernet/hysteria/app/v2/cmd.appDate=$(HYSTERIA_DATE) \
			-X github.com/apernet/hysteria/app/v2/cmd.appType=OpenWrt \
			-X github.com/apernet/hysteria/app/v2/cmd.appToolchain=$(HYSTERIA_TOOLCHAIN) \
			-X github.com/apernet/hysteria/app/v2/cmd.appCommit=$(HYSTERIA_COMMIT) \
			-X github.com/apernet/hysteria/app/v2/cmd.appPlatform=linux \
			-X github.com/apernet/hysteria/app/v2/cmd.appArch=$(GO_ARCH) \
			-X github.com/apernet/hysteria/app/v2/cmd.libVersion=$(HYSTERIA_QUIC)" \
			-o $(PKG_BUILD_DIR)/hysteria ./app
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(GO_ARCH) \
		python3 $(CURDIR)/../../tools/record-hysteria-producer.py \
			--binary $(PKG_BUILD_DIR)/hysteria --source $(PKG_BUILD_DIR) \
			--go "$(FOXHOLE_GO)" --architecture $(GO_ARCH) \
			--version $(PKG_VERSION) --source-sha256 $(PKG_HASH) \
			--source-commit $(HYSTERIA_COMMIT) \
			--output $(PKG_BUILD_DIR)/hysteria-producer.json \
			--test-suite "$(HYSTERIA_TEST_SUITE_INPUT)"
endef
endif

define Package/hysteria/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hysteria $(1)/usr/bin/hysteria
	$(INSTALL_DIR) $(1)/usr/share/foxhole
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/hysteria-producer.json $(1)/usr/share/foxhole/
	$(INSTALL_DIR) $(1)/usr/share/licenses/hysteria
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE.md \
		$(1)/usr/share/licenses/hysteria/LICENSE.md
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/app.LICENSE.md $(PKG_BUILD_DIR)/core.LICENSE.md \
		$(PKG_BUILD_DIR)/extras.LICENSE.md $(PKG_BUILD_DIR)/go-modules.json $(PKG_BUILD_DIR)/GO-THIRD-PARTY-NOTICES.txt \
		$(PKG_BUILD_DIR)/HYSTERIA-SOURCE-PATCH.patch $(PKG_BUILD_DIR)/HYSTERIA-PATCH-SOURCE.json \
		$(1)/usr/share/licenses/hysteria/
endef

$(eval $(call BuildPackage,hysteria))
