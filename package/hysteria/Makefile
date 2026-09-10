include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria
PKG_VERSION:=2.12.2
PKG_RELEASE:=2
PKG_SOURCE:=hysteria-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/apernet/hysteria/tar.gz/app/v$(PKG_VERSION)?
PKG_HASH:=8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e
PKG_SOURCE_SUBDIR:=hysteria-app-v$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)
PKG_BUILD_DEPENDS:=$(if $(FOXHOLE_GO),,golang/host)
PKG_BUILD_PARALLEL:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE.md app/LICENSE.md core/LICENSE.md extras/LICENSE.md
PKG_MAINTAINER:=FoxHole Team

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

FOXHOLE_GO?=$(STAGING_DIR_HOSTPKG)/lib/go-cross/bin/go
HYSTERIA_COMMIT:=619a6f856b69fb7ee6a7a379e810e68b84004605
HYSTERIA_QUIC:=v0.61.1-0.20260806010916-184d081eef3e
HYSTERIA_DATE:=2026-09-08
HYSTERIA_TOOLCHAIN:=$(shell $(FOXHOLE_GO) env GOVERSION 2>/dev/null)

define Package/hysteria
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Hysteria 2 upstream client
  URL:=https://github.com/apernet/hysteria
endef

define Package/hysteria/description
  Unmodified upstream Hysteria 2 client binary.
endef

define Build/Configure
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && $(GO_PKG_VARS) CGO_ENABLED=0 \
		$(FOXHOLE_GO) build \
			-trimpath -buildvcs=false \
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
endef

define Package/hysteria/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hysteria $(1)/usr/bin/hysteria
	$(INSTALL_DIR) $(1)/usr/share/licenses/hysteria
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE.md \
		$(1)/usr/share/licenses/hysteria/LICENSE.md
endef

$(eval $(call BuildPackage,hysteria))
