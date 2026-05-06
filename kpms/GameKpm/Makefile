#
# GameKpm — 游戏反检测专用 KPM
#   仅负责针对 TerSafe / TPRT 反作弊栈的运行期反检测
#   通用文件/进程/SO 隐藏委托给 inject-hide (kpm-svc)
#
# 用法：
#   make TARGET_COMPILE=/home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf- \
#        KP_DIR=../..
#

ifndef TARGET_COMPILE
TARGET_COMPILE := /home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf-
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 复用 inject-hide 的 Log/CStruct 头（用相对路径 include）
INCLUDE_FLAGS += -I../inject-hide

objs := \
    GameKpm.o \
    Common/Log.o \
    Common/Target.o \
    Common/Delegate.o \
    Anti/AntiDebug.o \
    Anti/AntiMem.o \
    Anti/AntiExec.o \
    Anti/AntiEnv.o \
    Anti/AntiPrivateDir.o \
    Status/StatusFilter.o

TARGET_NAME := game-kpm.kpm

all: $(TARGET_NAME)

$(TARGET_NAME): $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean push clean-remote

clean:
	rm -f $(TARGET_NAME)
	find . -name "*.o" | xargs rm -f

REMOTE_PATH := /sdcard/Download

push: all
	@echo "📤 推送 $(TARGET_NAME) → $(REMOTE_PATH)/"
	adb push $(TARGET_NAME) $(REMOTE_PATH)/$(TARGET_NAME)

clean-remote:
	@echo "🗑️  删除设备上的 $(TARGET_NAME)"
	adb shell rm -f $(REMOTE_PATH)/$(TARGET_NAME)
