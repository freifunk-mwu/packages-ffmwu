include $(TOPDIR)/rules.mk

PKG_NAME:=gluon-site-info
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/gluon-site-info
  SECTION:=gluon
  CATEGORY:=Gluon
  TITLE:=Add some scripts which announce site infos
  DEPENDS:=+gluon-core
endef

define Package/gluon-site-info/description
	This package add some scripts which announce site infos.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/gluon-site-info/install
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,gluon-site-info))
