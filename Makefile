ARCHS = arm64 arm64e
TARGET = iphone:14.0:latest
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShadowTrackerBypass

ShadowTrackerBypass_FILES = Tweak.xm fishhook/fishhook.c
ShadowTrackerBypass_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
ShadowTrackerBypass_LDFLAGS = -lssl -lcrypto -lz -lsubstrate
ShadowTrackerBypass_FRAMEWORKS = Foundation Security UIKit AdSupport AppTrackingTransparency

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 ShadowTrackerExtra || true"
