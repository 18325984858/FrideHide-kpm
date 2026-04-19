ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

#TARGET_COMPILE := /home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf-

ifndef KP_DIR
    KP_DIR = ../..
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := hello.o

all: hello.kpm

hello.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -Thello.lds -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f



# 定义手机上的目标路径
# 注意：Android 16 建议先推送到 /sdcard/Download 以便修改 SELinux 标签
REMOTE_PATH := /sdcard/Download
TARGET_NAME := hello.kpm

.PHONY: push
push: all
	@echo "📤 正在推送 $(TARGET) 到设备..."
	# 1. 推送文件到物理分区（绕过 /sdcard 的 FUSE 限制）
	adb push $(TARGET) $(REMOTE_PATH)/$(TARGET_NAME)
	
	@echo "🔧 正在修正权限与 SELinux 标签 (Android 16 必需)..."
	# 2. 设置 666 权限确保 APatch 可读
	adb shell "su -c 'chmod 666 $(REMOTE_PATH)/$(TARGET_NAME)'"
	# 3. 修正标签，否则加载时会报 rc: -1
	adb shell "su -c 'chcon u:object_r:shell_data_file:s0 $(REMOTE_PATH)/$(TARGET_NAME)'"
	
	@echo "✅ 推送完成！路径: $(REMOTE_PATH)/$(TARGET_NAME)"
	@echo "💡 提示：在 APatch 中加载时，请手动导航至 $(REMOTE_PATH)/$(TARGET_NAME) 目录选择该文件。"