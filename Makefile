include $(TOPDIR)/rules.mk

PKG_NAME:=WiZ_NG_Swan
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=nikhileshwar

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_SOURCE_LOCAL:=$(CURDIR)/files

PKG_BUILD_DEPENDS:=strongswan

TARGET_FULL:=$(shell ls -d $(TOPDIR)/build_dir/target-* | head -n 1 | sed 's|.*/build_dir/||')
ifneq ($(TARGET_FULL),)
 TARGET_FULL:=$(TARGET_FULL)
# else
#   $(error No target directory found in build_dir)
endif

STRONG_SWAN_DIR:=$(wildcard $(TOPDIR)/build_dir/$(TARGET_FULL)/strongswan-*)
ifneq ($(STRONG_SWAN_DIR),)
  STRONGSWAN_VERSION:=$(notdir $(firstword $(STRONG_SWAN_DIR)))
# else
#   $(error StrongSwan build directory not found in build_dir/$(TARGET_FULL))
endif

TARGET_CFLAGS += -Wall -Werror -pedantic -fstack-protector-strong
LIBVICI = -I$(TOPDIR)/build_dir/$(TARGET_FULL)/$(STRONGSWAN_VERSION)/src/libcharon/plugins/vici
VICI = -L$(TOPDIR)/build_dir/$(TARGET_FULL)/$(STRONGSWAN_VERSION)/ipkg-install/usr/lib/ipsec -lvici -lstrongswan -Wl,-rpath=/usr/lib/ipsec
LIB_NAENCRYPT_H = -I$(TOPDIR)/build_dir/$(TARGET_FULL)/WiZ_NG_Encrypt-1.0
LIB_NAENCRYPT = -L$(TOPDIR)/build_dir/$(TARGET_FULL)/WiZ_NG_Encrypt-1.0 -lna_encrypt
include $(INCLUDE_DIR)/package.mk

define Package/WiZ_NG_Swan
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=IPsec VICI Interface Library and Tool
	DEPENDS:=+strongswan-mod-vici +WiZ_NG_Encrypt
endef

define Package/WiZ_NG_Swan/description
	A library and tool for managing IPsec connections via VICI
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) $(PKG_SOURCE_LOCAL)/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -fPIC -shared -g \
		-o $(PKG_BUILD_DIR)/libipsecvici.so \
		$(PKG_BUILD_DIR)/ipsecvici.c $(LIBVICI) $(VICI) $(LIB_NAENCRYPT_H) $(LIB_NAENCRYPT)

	$(TARGET_CC) $(TARGET_CFLAGS) -g \
		-o $(PKG_BUILD_DIR)/ipsecvici \
		$(PKG_BUILD_DIR)/ipsecvici_main.c \
		-L$(PKG_BUILD_DIR) -lipsecvici $(LIBVICI) $(VICI) $(LIB_NAENCRYPT_H) $(LIB_NAENCRYPT)

	$(TARGET_CC) $(TARGET_CFLAGS) -g \
	-o $(PKG_BUILD_DIR)/uptime \
	$(PKG_BUILD_DIR)/uptime.c \
	-L$(PKG_BUILD_DIR) $(LIBVICI) $(VICI)
endef

define Package/WiZ_NG_Swan/install
	$(INSTALL_DIR) $(1)/usr/lib/ipsec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipsecvici.so $(1)/usr/lib/ipsec
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipsecvici $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/share/swanctl/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uptime $(1)/usr/share/swanctl
endef

$(eval $(call BuildPackage,WiZ_NG_Swan))
