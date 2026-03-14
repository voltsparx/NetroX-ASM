NASM ?= nasm
LD ?= ld

BUILD_DIR := build/linux
SRC_DIR := src/linux
WIN_BUILD_DIR := build/win
WIN_SRC_DIR := src/windows
MINGW_LD ?= x86_64-w64-mingw32-ld

LINUX_OBJS := $(BUILD_DIR)/main.o
WIN_OBJS := $(WIN_BUILD_DIR)/main.obj

.PHONY: all linux windows clean

all: linux windows

linux: $(LINUX_OBJS)
	$(LD) -o netx-asm $(LINUX_OBJS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.asm src/common/constants.inc src/common/parse.inc src/common/checksum.inc src/common/packet.inc src/common/engine.inc src/common/scan.inc
	@mkdir -p $(BUILD_DIR)
	$(NASM) -f elf64 -D LINUX $< -o $@

windows: $(WIN_OBJS)
	$(MINGW_LD) -o netx-asm.exe $(WIN_OBJS) -lws2_32 -lkernel32

$(WIN_BUILD_DIR)/main.obj: $(WIN_SRC_DIR)/main.asm src/common/parse.inc src/common/checksum.inc src/common/packet.inc src/common/engine.inc src/common/scan.inc
	@mkdir -p $(WIN_BUILD_DIR)
	$(NASM) -f win64 -D WINDOWS $< -o $@

clean:
	rm -rf build netx-asm netx-asm.exe
