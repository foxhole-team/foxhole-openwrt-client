include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria-ram
PKG_VERSION:=2.12.2
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=FoxHole Team

include $(INCLUDE_DIR)/package.mk

define Package/hysteria-ram
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Pinned upstream Hysteria 2 in volatile storage (ARM64)
  DEPENDS:=@aarch64 +uclient-fetch +ca-bundle +flock
  PROVIDES:=hysteria
  CONFLICTS:=hysteria
  PKGARCH:=all
endef

define Package/hysteria-ram/description
  Small-flash alternative to the persistent Hysteria binary. Downloads
  upstream 2.12.2 to private RAM storage and verifies its pinned SHA256.
  Requires ARM64, network access after boot, and 32 MiB free RAM for
  binary storage in addition to the running process working set.
endef

define Build/Compile
endef

define Package/hysteria-ram/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/hysteria $(1)/usr/bin/hysteria
endef

$(eval $(call BuildPackage,hysteria-ram))
