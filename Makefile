# DeltaSkin — build a standalone arm64 dylib for iOS 14.0+
#
# Requires macOS + Xcode command line tools (xcrun). On Windows/Linux use the
# GitHub Actions workflow instead, or build inside WSL with a toolchain that
# ships the iPhoneOS SDK.

SDK      := $(shell xcrun --sdk iphoneos --show-sdk-path)
MIN      := 14.0
SRC      := src/DeltaSkin.mm
OUT      := build/DeltaSkin.dylib
ARCHS    := -arch arm64

CFLAGS   := -isysroot $(SDK) -miphoneos-version-min=$(MIN) -fobjc-arc -O2 \
            -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations
LDFLAGS  := -dynamiclib -framework Foundation -framework UIKit -framework CoreGraphics

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p build
	xcrun --sdk iphoneos clang $(ARCHS) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "built $@"

clean:
	rm -rf build

.PHONY: all clean
