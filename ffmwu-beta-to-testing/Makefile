include $(TOPDIR)/rules.mk

PKG_NAME:=ffmwu-beta-to-testing
PKG_VERSION:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include ../../../package/gluon.mk

define Package/ffmwu-beta-to-testing
  SECTION:=gluon
  CATEGORY:=Gluon
  TITLE:=Replace beta with testing branch
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
	$(call GluonSrcDiet,./luasrc,$(PKG_BUILD_DIR)/luadest/)
endef

define Package/ffmwu-beta-to-testing/install
	$(CP) $(PKG_BUILD_DIR)/luadest/* $(1)/
endef

$(eval $(call BuildPackage,ffmwu-beta-to-testing))
