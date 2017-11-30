include $(TOPDIR)/rules.mk

PKG_NAME:=ffmwu-set-domain-code
PKG_VERSION:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include ../../../package/gluon.mk

define Package/ffmwu-set-domain-code
  SECTION:=gluon
  CATEGORY:=Gluon
  TITLE:=Initially set domain code (from site code)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
	$(call GluonSrcDiet,./luasrc,$(PKG_BUILD_DIR)/luadest/)
endef

define Package/ffmwu-set-domain-code/install
	$(CP) ./files/* $(1)/
	$(CP) $(PKG_BUILD_DIR)/luadest/* $(1)/
endef

$(eval $(call BuildPackage,ffmwu-set-domain-code))
