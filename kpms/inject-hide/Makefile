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

objs := inject-hide.o

all: inject-hide.kpm

inject-hide.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -T inject-hide.lds -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f



# 定义手机上的目标路径
# 注意：Android 16 建议先推送到 /sdcard/Download 以便修改 SELinux 标签
REMOTE_PATH := /sdcard/Download
TARGET_NAME := inject-hide.kpm

.PHONY: push
push: all
	@echo "📤 正在推送 $(TARGET) 到设备..."
	adb push $(TARGET_NAME) $(REMOTE_PATH)/$(TARGET_NAME)