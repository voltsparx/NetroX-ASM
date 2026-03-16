NASM      ?= nasm
CXX       ?= g++
MINGW_CXX ?= x86_64-w64-mingw32-g++

BIN_DIR       := bin
BUILD_DIR     := build
LINUX_OBJ_DIR := $(BUILD_DIR)/linux
WIN_OBJ_DIR   := $(BUILD_DIR)/win

CXXFLAGS := -std=c++17 -O2 -fno-exceptions -fno-rtti -I include

LINUX_ASM_SRCS := src/asm/linux/scan_core.asm src/asm/linux/network.asm src/asm/linux/data.asm
WIN_ASM_SRCS   := src/asm/windows/scan_core.asm src/asm/windows/network.asm src/asm/windows/data.asm

CPP_SRCS := $(wildcard src/cpp/*.cpp)

LINUX_ASM_OBJS := $(LINUX_ASM_SRCS:src/asm/linux/%.asm=$(LINUX_OBJ_DIR)/%.o)
WIN_ASM_OBJS   := $(WIN_ASM_SRCS:src/asm/windows/%.asm=$(WIN_OBJ_DIR)/%.obj)
LINUX_CPP_OBJS := $(CPP_SRCS:src/cpp/%.cpp=$(LINUX_OBJ_DIR)/cpp/%.o)
WIN_CPP_OBJS   := $(CPP_SRCS:src/cpp/%.cpp=$(WIN_OBJ_DIR)/cpp/%.obj)

.PHONY: all linux windows clean install uninstall update test-install

all: linux windows

linux: $(LINUX_ASM_OBJS) $(LINUX_CPP_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LINUX_ASM_OBJS) $(LINUX_CPP_OBJS) -o $(BIN_DIR)/netrox-asc
	@echo "[+] Linux build: $(BIN_DIR)/netrox-asc"

windows: $(WIN_ASM_OBJS) $(WIN_CPP_OBJS)
	@mkdir -p $(BIN_DIR)
	$(MINGW_CXX) $(WIN_ASM_OBJS) $(WIN_CPP_OBJS) -o $(BIN_DIR)/netrox-asc.exe -lws2_32 -lkernel32
	@echo "[+] Windows build: $(BIN_DIR)/netrox-asc.exe"

$(LINUX_OBJ_DIR)/%.o: src/asm/linux/%.asm include/netrox_abi.h
	@mkdir -p $(LINUX_OBJ_DIR)
	$(NASM) -f elf64 -D LINUX -I src/asm/common/ $< -o $@

$(WIN_OBJ_DIR)/%.obj: src/asm/windows/%.asm include/netrox_abi.h
	@mkdir -p $(WIN_OBJ_DIR)
	$(NASM) -f win64 -D WINDOWS -I src/asm/common/ $< -o $@

$(LINUX_OBJ_DIR)/cpp/%.o: src/cpp/%.cpp include/netrox_abi.h
	@mkdir -p $(LINUX_OBJ_DIR)/cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(WIN_OBJ_DIR)/cpp/%.obj: src/cpp/%.cpp include/netrox_abi.h
	@mkdir -p $(WIN_OBJ_DIR)/cpp
	$(MINGW_CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf build $(BIN_DIR)

install:
	@echo "[*] Running Linux installer..."
	@chmod +x install-scripts/install.sh
	@sudo install-scripts/install.sh install

uninstall:
	@echo "[*] Running Linux uninstaller..."
	@chmod +x install-scripts/install.sh
	@sudo install-scripts/install.sh uninstall

update:
	@echo "[*] Running Linux updater..."
	@chmod +x install-scripts/install.sh
	@sudo install-scripts/install.sh update

test-install:
	@echo "[*] Running test suite..."
	@chmod +x install-scripts/install.sh
	@install-scripts/install.sh test
