---
applyTo: "**"
description: FrideHide-kpm 项目记忆 — Copilot 每次会话必读
---

# 项目: FrideHide-kpm（KernelPatch 衍生 / 隐藏 Root 痕迹）

## 技术栈

- **语言**: C（内核 + KPM 模块）+ ARM64 内联汇编 + 少量 C++（kpms/）
- **运行环境**: Android 内核（aarch64），通过 KernelPatch 加载到运行中的内核
- **工具链**: NDK clang (`aarch64-linux-android*-clang`)，宿主端用系统 clang/gcc
- **用户态工具**: `tools/` 下 `kptools`（CMake），`user/` 提供 `supercall.h` superhook ABI

## 目录约定

| 路径               | 内容                                                    | 修改约束                        |
| ------------------ | ------------------------------------------------------- | ------------------------------- |
| `kernel/`          | 内核补丁源 + 链接脚本 (`kpimg.lds`)                     | 与 KernelPatch 上游强相关，慎改 |
| `kpms/<name>/`     | 可加载内核模块（demo-hello / inject-hide / GameKpm 等） | 每个模块独立 Makefile           |
| `tools/`           | 宿主端 `kptools` 二进制（解析 kallsyms / 补丁镜像）     | CMake 构建                      |
| `user/supercall.h` | 用户态 ↔ KPM 的 syscall ABI 头                          | 改动需同步 kpms 内核侧          |
| `user_deprecated/` | 旧版用户工具，**不要在此实现新功能**                    | 只读                            |

## 构建

```bash
# 宿主端 kptools
cd tools && make
# 或 cmake -B build && cmake --build build

# 内核 KPM 模块（示例：inject-hide）
make -C kpms/inject-hide
```

## 设备热加载（来自实测）

- `kpatch` 在普通 `adb shell` 下能接受 superkey；用 `su -c` 包装可能返回 `invalid superkey`
- 热重载 `svc.kpm`：先 `adb push` 到 `/data/local/tmp/`，然后
  `kpatch <key> kpm unload kpm-svc && kpatch <key> kpm load /data/local/tmp/svc.kpm`

## 代码风格

- 4 空格缩进，Linux kernel 风格（函数大括号同行/换行按文件惯例）
- KPM 模块 **不允许引入 libc**，只用内核头（`linux/`）与 KernelPatch 提供的 API
- 公共 ABI 改动须同时改 `user/supercall.h` 与对应 KPM 的 hook 表

## 已知陷阱

- Android linker 报 `libdobbyproject.so is not accessible for namespace clns-*` 通常是 readlink spoof 把 `/proc/self/fd/*` 指向了 app 自己 `/data/app/.../lib/arm64/*.so`，须放行这类路径
- KPM 内核侧符号解析依赖 `kallsym.c` 输出；改动符号匹配规则要回归 `tools/` 测试用例

## 任务约束（Hook）

- 改完 `tools/**.c` → 必须运行 task `kptools: build`
- 改完 `kpms/<m>/**` → 必须运行 task `kpm: build <m>` 并贴出 `.kpm` 文件 size 与 readelf 摘要
- 涉及 `user/supercall.h` 改动 → 同时报告影响到的所有 KPM 文件清单
