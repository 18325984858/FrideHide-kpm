#ifndef TARGET_COMPILE
#    $(error TARGET_COMPILE not set)
#endif

TARGET_COMPILE := /home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf-

ifndef KP_DIR
    KP_DIR = ../..
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := inject-hide.o Frid/FridHide.o Config/Log.o Config/Config.o Debug/Debug.o

all: svc.kpm

svc.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f



REMOTE_PATH := /sdcard/Download
TARGET_NAME := svc.kpm

.PHONY: push clean-remote

push: all
	@echo "📤 正在推送 $(TARGET_NAME) 到设备..."
	adb push $(TARGET_NAME) $(REMOTE_PATH)/$(TARGET_NAME)

# 新增：删除远程目录下的目标文件
clean-remote:
	@echo "🗑️  正在删除设备上的 $(TARGET_NAME)..."
	adb shell rm -f $(REMOTE_PATH)/$(TARGET_NAME)

	# 新增：删除远程目录下的所有文件 (危险操作，请确认路径)
clean-all-remote:
	@echo "🔥 正在清空设备目录: $(REMOTE_PATH) ..."
	adb shell "rm -rf $(REMOTE_PATH)/*"