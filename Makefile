NASM      ?= nasm
LD        ?= ld
MINGW_LD  ?= x86_64-w64-mingw32-ld

BUILD_DIR     := build/linux
SRC_DIR       := src/linux
WIN_BUILD_DIR := build/win
WIN_SRC_DIR   := src/windows

COMMON_DEPS := src/common/constants.inc \
               src/common/scan.inc \
               src/common/parse.inc \
               src/common/checksum.inc \
               src/common/packet.inc \
               src/common/engine.inc

LINUX_OBJS := $(BUILD_DIR)/main.o
WIN_OBJS   := $(WIN_BUILD_DIR)/main.obj

.PHONY: all linux windows clean

all: linux windows

# ---------------------------------------------------------------
# Linux build:  single statically linked ELF64, no shared libs
# ---------------------------------------------------------------
linux: $(BUILD_DIR)/main.o
	$(LD) -o netrox-asm $(BUILD_DIR)/main.o
	@echo "[+] Linux build: netrox-asm"
	@ls -lh netrox-asm

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.asm $(COMMON_DEPS)
	@mkdir -p $(BUILD_DIR)
	$(NASM) -f elf64 -D LINUX $< -o $@

# ---------------------------------------------------------------
# Windows build: PE64, only ws2_32 + kernel32 imports
# ---------------------------------------------------------------
windows: $(WIN_BUILD_DIR)/main.obj
	$(MINGW_LD) -o netrox-asm.exe $(WIN_BUILD_DIR)/main.obj \
		-lws2_32 -lkernel32
	@echo "[+] Windows build: netrox-asm.exe"
	@ls -lh netrox-asm.exe

$(WIN_BUILD_DIR)/main.obj: $(WIN_SRC_DIR)/main.asm $(COMMON_DEPS)
	@mkdir -p $(WIN_BUILD_DIR)
	$(NASM) -f win64 -D WINDOWS $< -o $@

# ---------------------------------------------------------------
# Clean
# ---------------------------------------------------------------
clean:
	rm -rf build netrox-asm netrox-asm.exe