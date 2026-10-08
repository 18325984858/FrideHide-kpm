# FrideHide-kpm

> 基于 [KernelPatch](https://github.com/bmax121/KernelPatch)（上游 v0.12.9）的 Android 内核态隐藏 / 反检测 KPM 集合。
> 当前包含两个生产模块：**inject-hide**（通用隐藏） + **GameKpm**（游戏反作弊穿透）。
> 为 Pixel 8 (Android 14, kernel 6.1) + APatch / KernelPatch 用户态环境调试。

```
 _  __                    _ ____       _       _     
| |/ /___ _ __ _ __   ___| |  _ \ __ _| |_ ___| |__  
| ' // _ \ '__| '_ \ / _ \ | |_) / _` | __/ __| '_ \ 
| . \  __/ |  | | | |  __/ |  __/ (_| | || (__| | | |
|_|\_\___|_|  |_| |_|\___|_|_|   \__,_|\__\___|_| |_|
```

仅供安全研究与个人技术学习使用。

---

## 目录

- [项目定位](#项目定位)
- [版本与组成](#版本与组成)
- [架构总览](#架构总览)
- [目录层次](#目录层次)
- [模块枚举：inject-hide](#模块枚举inject-hidekpm-svc)
- [模块枚举：GameKpm](#模块枚举gamekpmgame-kpm)
- [模块枚举：demo 示例](#模块枚举demo-示例)
- [基座枚举：KernelPatch](#基座枚举kernelpatch)
- [编译环境要求](#编译环境要求)
- [编译步骤](#编译步骤)
- [部署与加载](#部署与加载)
- [使用说明](#使用说明)
- [配套 Android 应用](#配套-android-应用)
- [稳定性 / 已知约束](#稳定性--已知约束)
- [仓库自动化配置](#仓库自动化配置)

---

## 项目定位

本仓库 = **KernelPatch 上游基座（未改动核心逻辑）** + **两个自研生产级 KPM**。

| 层面 | 内容 | 归属 |
|---|---|---|
| 基座 | kpimg（内核补丁镜像）、kptools（宿主机补丁工具）、kuser ABI 头 | 上游 [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) |
| 模块 | `inject-hide`、`GameKpm`、3 个 demo | 本仓库增量 |
| 用户态 | `kpatch` CLI、shell 编排脚本、配套 APK | 本仓库 / [18325984858/game](https://github.com/18325984858/game) |

---

## 版本与组成

| 项 | 值 |
|---|---|
| KernelPatch 基座版本 | `0.12.9`（见 [`version`](./version)：MAJOR 0 / MINOR 12 / PATCH 9） |
| KPM: inject-hide | `kpm-svc` v1.0.0 — 产物 `kpms/inject-hide/svc.kpm`（92,984 B ≈ 91 KB） |
| KPM: GameKpm | `game-kpm` v0.1.0 — 产物 `kpms/GameKpm/game-kpm.kpm`（62,840 B ≈ 61 KB） |
| License | GPL v2 |

两个 KPM **协同工作**：GameKpm 处理游戏专属反检测（TerSafe / TPRT），inject-hide 提供通用隐藏底座。

---

## 架构总览

### 分层架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 用户态 (Android userspace)                                               │
│                                                                          │
│   APatch / KernelPatch App        kpatch CLI            shell 编排脚本    │
│   ├─ kp_ctl.cpp (SUPERCALL_KPM_CONTROL)  ├─ kpm load/unload  ├─ game_reload.sh
│   └─ assets/*.kpm (一键安装)             ├─ kpm ctl0 <name> <cmd>  └─ auto_test.sh
└───────────────────────────┬──────────────────────────────────────────────┘
                            │  SuperCall (syscall 号在 scdefs.h)
┌───────────────────────────▼──────────────────────────────────────────────┐
│ 内核态 (kpimg — KernelPatch 基座，kernel/)                                │
│                                                                          │
│   patch.c        启动接管 / 补丁流程                                       │
│   common/syscall.c      系统调用替换 (0x1000..0x11xx SuperCall 分发)        │
│   common/supercall.c    SuperCall 内核实现（kpm load/ctl0/info/list…）      │
│   common/supercmd.c     SuperKey 命令行 (kpatch 子命令)                    │
│   common/kstorage.c     内核态 key-value 存储                             │
│   common/sucompat.c     su 兼容层（UID 授权 → root）                       │
│   common/accctl.c       访问控制 / allow list                            │
│   common/secpass.c      SELinux 绕过                                     │
│   module/module.c       ★ KPM ELF 加载器 / 生命周期                        │
│   module/relo.c / insn.c  KPM 重定位 / ARM64 指令解析                      │
│   base/hook.c           ★ inline hook + hook chain                       │
│   base/fphook.c         函数指针 hook                                     │
│   base/hotpatch.c       热补丁框架                                        │
│   base/{symbol,kallsyms}.c  符号解析                                      │
│   base/tlsf.c           内核态内存分配器                                   │
└───────────────────────────┬──────────────────────────────────────────────┘
                            │  KPM ABI (KPM_INIT / KPM_CTL0 / KPM_EXIT)
┌───────────────────────────▼──────────────────────────────────────────────┐
│ KPM 模块层 (kpms/)                                                       │
│                                                                          │
│   inject-hide (kpm-svc)                GameKpm (game-kpm)                │
│   ├─ Frid/FridHide.c   主 hook 框架     ├─ Anti/AntiDebug.c  ptrace/prctl/pts
│   ├─ Root/RootHide.c   Root 痕迹隐藏    ├─ Anti/AntiMem.c    mincore 谎报
│   ├─ Config/Log.c      日志/配置        ├─ Anti/AntiExec.c   execve/inotify
│   ├─ Debug/Debug.c     调试辅助         ├─ Anti/AntiEnv.c    uname 改写
│   └─ Struct/CStruct.h  内核结构偏移      ├─ Anti/AntiPrivateDir.c 目录观测
│                                        ├─ Status/StatusFilter.c TracerPid
│                                        ├─ Common/{Log,Target,Delegate}.c
│                                        └─ GameKpm.c  入口 + control0 分发
└──────────────────────────────────────────────────────────────────────────┘
```

### 控制流（一次 ctl0 命令的完整路径）

```
adb shell su -c 'kpatch <SK> kpm ctl0 game-kpm preset_dfm'
  → SUPERCALL_KPM_CONTROL (0x1022)
  → kpimg: patch/module/module.c: kpm_ctl0()
  → KPM:   GameKpm.c: game_kpm_control0(args, out_msg, outlen)
  → 命中 "preset_dfm" → 置 8 个开关 + delegate_preset_dfm()
       └─ Common/Delegate.c → module_control0("kpm-svc", "add_hide_pkg:…")
  → compat_copy_to_user(out_msg, …) 回写结果
```

### 关键 ABI

| 接口 | 位置 | 说明 |
|---|---|---|
| `KPM_NAME/VERSION/LICENSE/AUTHOR/DESCRIPTION` | [`kernel/include/kpmodule.h`](./kernel/include/kpmodule.h) | KPM 元信息（有长度上限） |
| `KPM_INIT / KPM_CTL0 / KPM_CTL1 / KPM_EXIT` | 同上 | 四个生命周期钩子 |
| `hook_wrapN() / fp_hook_syscalln() / unhook()` | [`kernel/include/hook.h`](./kernel/include/hook.h) | 内核函数与 syscall hook |
| `compat_copy_to_user / compat_strncpy_from_user` | [`kernel/patch/include/kputils.h`](./kernel/patch/include/kputils.h) | 用户态内存安全访问 |
| `SUPERCALL_*` | [`kernel/patch/include/uapi/scdefs.h`](./kernel/patch/include/uapi/scdefs.h) | 用户态 ↔ 内核 SuperCall 号 |

---

## 目录层次

```
FrideHide-kpm/
├── README.md
├── LICENSE                         GPL v2
├── version                         0.12.9 (MAJOR/MINOR/PATCH)
├── banner  doxyfile  .clang-format
│
├── kernel/                         KernelPatch 内核侧（kpimg）
│   ├── kpimg.lds  Makefile
│   ├── base/                       hook / fphook / hotpatch / tlsf / symbol / map / setup / start
│   ├── include/                    KPM 公开头：hook.h / kpmodule.h / log.h / common.h / preset.h
│   ├── linux/                      内核 UAPI / asm-generic / arch/arm64 头子集（无源码树编译用）
│   └── patch/
│       ├── patch.c                 启动接管与补丁主流程
│       ├── common/                 syscall / supercall / supercmd / kstorage / sucompat / accctl
│       │                           secpass / sysname / taskob / user_event / utils / test
│       ├── module/                 module.c（KPM 加载器）/ relo.c / insn.c
│       ├── ksyms/                  libs.c / misc.c / task_cred.c / execv.c（内核符号导出）
│       ├── android/                sepolicy_flags / userd / gen/user_init（Android 特性）
│       └── include/uapi/scdefs.h   ★ SuperCall ABI
│
├── kpms/                           ★ KPM 模块源码 ★
│   ├── demo-hello/                 最小示例（hello.c）
│   ├── demo-inlinehook/            inline hook 示例（inlinehook.c）
│   ├── demo-syscallhook/           syscall hook 示例（syscallhook.c）
│   ├── inject-hide/                ★ 通用隐藏 (kpm-svc)
│   │   ├── inject-hide.c           入口 + control0 命令分发
│   │   ├── Frid/FridHide.{c,h}     主 hook 实现（show_map_vma/openat/read/…）
│   │   ├── Root/RootHide.{c,h}     Root 痕迹隐藏（60+ 关键词 + 豁免名单）
│   │   ├── Config/{Log,Config}.{c,h}  日志宏（klog/klog_dbg/klog_err/klog_always）+ 配置占位
│   │   ├── Debug/Debug.{c,h}       调试占位
│   │   ├── Struct/CStruct.h        seq_file / sockaddr_in 结构定义
│   │   ├── Makefile
│   │   └── svc.kpm                 (编译产物，已入库)
│   └── GameKpm/                    ★ 游戏反作弊 (game-kpm)
│       ├── GameKpm.c               入口 + control0 命令分发
│       ├── PLAN.md                 设计 / 分工 / 实施计划
│       ├── Common/
│       │   ├── Log.{h,c}           独立 [GAMEKPM] 日志通道
│       │   ├── Target.{h,c}        目标判定（comm 前缀 + tgid + fullname 三层）
│       │   └── Delegate.{h,c}      module_control0 IPC 桥 → kpm-svc
│       ├── Anti/
│       │   ├── AntiDebug.{h,c}     ptrace / prctl / openat(/dev/pts) / write(comm)
│       │   ├── AntiMem.{h,c}       mincore 谎报
│       │   ├── AntiExec.{h,c}      execve / inotify_add_watch
│       │   ├── AntiEnv.{h,c}       uname 改写
│       │   └── AntiPrivateDir.{h,c} 游戏私有目录访问观测
│       ├── Status/StatusFilter.{h,c}  /proc/self/status TracerPid 过滤
│       ├── tools/
│       │   ├── game_reload.sh      一键卸载/加载/启动游戏/注册 tgid
│       │   └── auto_test.sh        自动化回归（build+push+采样，默认 DFM 30s）
│       ├── Makefile
│       └── game-kpm.kpm            (编译产物，已入库)
│
├── tools/                          宿主机 kptools（CMake + Makefile）
│   └── image.c kallsym.c kptools.c order.c insn.c patch.c symbol.c kpm.c common.c sha256.c
│
├── user/                           导出的 kuser ABI 头（supercall.h + version，由 kernel `make hdr` 生成）
├── user_deprecated/                旧版用户态工具（kpatch CLI 源码：main.c/kpatch.c/kpm.c/su.c…）
│                                   ⚠ 只读，不在此实现新功能
└── .github/                        CI + Copilot 配置（见「仓库自动化配置」）
```

---

## 模块枚举：inject-hide（kpm-svc）

> 产物：`kpms/inject-hide/svc.kpm` · 源文件 7 个 · 定位：**通用隐藏底座**

### 源文件职责

| 文件 | 职责 |
|---|---|
| [inject-hide.c](./kpms/inject-hide/inject-hide.c) | `KPM_INIT/CTL0/CTL1/EXIT` 入口；control0 命令分发 |
| [Frid/FridHide.c](./kpms/inject-hide/Frid/FridHide.c) | 主 hook 实现、hide_so/pid/pkg/comm 列表、read 内容过滤、属性伪装 |
| [Root/RootHide.c](./kpms/inject-hide/Root/RootHide.c) | Root 关键词库、UID/包名豁免、Root 守护进程 comm 识别 |
| [Config/Log.{c,h}](./kpms/inject-hide/Config/Log.h) | `[SFK]` 前缀分级日志：`klog` / `klog_dbg` 受 `kpm_log_enabled` 控制，`klog_err` / `klog_always` 始终输出 |
| [Config/Config.{c,h}](./kpms/inject-hide/Config/Config.h) | 配置占位（留空待扩展） |
| [Debug/Debug.{c,h}](./kpms/inject-hide/Debug/Debug.h) | 调试占位（留空待扩展） |
| [Struct/CStruct.h](./kpms/inject-hide/Struct/CStruct.h) | 内核/网络结构偏移：`struct seq_file`（hook show_* 时手工解析缓冲区）、`struct sockaddr_in`（connect hook 取端口） |

### 内核函数 hook

| hook 点 | 方式 | 行为 |
|---|---|---|
| `show_map_vma` | `hook_wrap2` before/after | `/proc/<pid>/maps` 行级隐藏命中 hide_so / root_kw 的行 |
| `show_smap_vma` | `hook_wrap2` before/after | `/proc/<pid>/smaps` 同上 |
| `show_mountinfo` | `hook_wrap2` before/after | `/proc/self/mountinfo` 丢弃含 root_kw（含 `/debug_ramdisk`）的行 |
| `show_vfsmnt` | `hook_wrap2` before/after | `/proc/self/mounts` 同上 |
| `__get_task_comm` | `hook_wrap3` after | 线程名命中 hide_comm → 擦写为空格；命中 hide_pkg → 自动注册 tgid |
| `__system_property_get` | `hook_wrap2` after | 属性伪装（`prop_spoofs[]` 表，见下） |

### 系统调用 hook

| syscall | 阶段 | 行为 |
|---|---|---|
| `__NR_openat` / `__NR_openat2` | before + after | 路径命中 hide_so / root_kw → `-ENOENT`；after 记录 fd→path 供 read 分流 |
| `__NR_close` | before | 清理 fd→path 映射 |
| `__NR_faccessat` / `__NR_faccessat2` | before | 命中同上 → `-ENOENT`（防存在性探测） |
| `__NR_getdents64` | after | `/proc` 目录项过滤 hide_pid 子目录 |
| `__NR_read` / `__NR_pread64` | after | 按 fd 路径分流：`cmdline` / `mounts` / `status` 行级删除或替换；属性串伪装 |
| `__NR3264_fstatat` / `__NR_statx` | before | stat 系列路径命中 → `-ENOENT` |
| `__NR_readlinkat` | before + after | 隐藏指向被隐藏 SO 的软链（放行 app 自身 `/data/app/.../lib/arm64/*.so`） |
| `__NR_execve` / `__NR_execveat` | before | basename ∈ {su, magisk, ksud, getprop, …} → `-ENOENT` |
| `__NR_connect` | before | 屏蔽非 adbd 进程对 `127.0.0.1:27042`（frida-agent）的连接 |

### 运行时列表与数据结构

| 列表 | 容量 | 默认种子 | 用途 |
|---|---|---|---|
| `custom_hide_so[]` | 256 × 128 B | `libdobbyproject`, `libdobby`, `dobby`, `frida-agent`, `frida` | 路径/maps 关键词 |
| `custom_hide_comm[]` | 32 × 32 B | `gmain`, `gum-js-loop`, `GumJS`, `gdbus`, `pool-frida`, `linjector` | 线程名擦写关键词 |
| `custom_hide_pid[]` | 16 | — | `/proc` 目录项 + `/proc/<pid>/*` 隐藏 |
| `custom_hide_pkg[]` | 16 × 128 B | `com.example.dobbyproject` | 包名 → 自动注册 tgid 并开启 proc_hide |
| `root_kw[]` | 默认 60+ | su / magisk / ksu / apatch / lsposed / shamiko / zygisk / tricky … | Root 痕迹关键词 |
| `exempt_uid[]` | — | 运行时自动加入调用方 | Root 豁免 UID |
| `exempt_pkg[]` | — | `me.bmax.apatch`, `com.example.dobbyproject` | 按 `task->comm` 15 B 前缀豁免 |
| `root_daemon_comm[]` | 固定表 | `magiskd` `ksud` `apd` `kpatchd` `zygiskd` `shamiko` `tricky_store` … | Root 守护进程识别 |

**内容过滤指纹（`sensitive_span_match`）**：只对同时命中 hide_so / hide_comm / root_kw 关键字的缓冲区动手，避免误伤。

**属性伪装表（`prop_spoofs[]`）**：

| 属性 | 伪装值 |
|---|---|
| `ro.boot.verifiedbootstate` | `green` |
| `ro.boot.vbmeta.device_state` | `locked` |
| `ro.boot.flash.locked` | `1` |
| `ro.boot.veritymode` | `enforcing` |
| `ro.boot.warranty_bit` / `ro.warranty_bit` | `0` |
| `ro.debuggable` | `0` |
| `ro.secure` | `1` |
| `ro.build.type` | `user` |
| `ro.build.tags` | `release-keys` |
| `ro.boot.selinux` | `enforcing` |
| `sys.oem_unlock_allowed` | `""`（空串 ≡ 属性不存在） |
| `ro.oem_unlock_supported` | `0` |
| `ro.boot.realmebootstate` | `green` |
| `ro.boot.hwc` | `GLOBAL` |

> 未导出 `__system_property_get` 时，退化为 **read 缓冲区**属性伪装路径（仍覆盖同表）。

### control0 命令全集

> 统一调用格式：`kpatch <SUPERKEY> kpm ctl0 kpm-svc <cmd>`

**开关类**

| 命令 | 说明 |
|---|---|
| `enable_file_hide` / `disable_file_hide` | 文件级隐藏（openat/faccessat 拦截） |
| `enable_comm_hide` / `disable_comm_hide` | 线程名擦写 |
| `enable_proc_hide` / `disable_proc_hide` | `/proc/<pid>` 目录级隐藏 |
| `enable_sys_exempt` / `disable_sys_exempt` | 系统进程豁免（默认开） |
| `set_sys_exempt_uid:<N>` | 豁免 UID 阈值（默认 10000） |
| `enable_root_hide` / `disable_root_hide` | Root 痕迹隐藏（默认开） |
| `enable_log` / `disable_log` | 内核日志总开关 |

**SO 列表**：`add_hide_so:<n1>,<n2>,…` · `remove_hide_so:<name>` · `list_hide_so` · `clear_hide_so`

**包名列表**：`add_hide_pkg:<n1>,<n2>,…` · `remove_hide_pkg:<name>` · `list_hide_pkg` · `clear_hide_pkg`

**线程名列表**：`add_hide_comm:<n1>,<n2>,…` · `remove_hide_comm:<name>` · `list_hide_comm` · `clear_hide_comm`

**PID 列表**：`add_hide_pid:<pid>[,<pid>…]` · `remove_hide_pid:<pid>` · `list_hide_pid` · `clear_hide_pid`

**Root 关键词**：`add_hide_root:<n1>,<n2>,…` · `remove_hide_root:<name>` · `list_hide_root` · `clear_hide_root` · `reset_hide_root`

**豁免名单**：`add_exempt_self` · `add_exempt_uid:<uid>` · `remove_exempt_uid:<uid>` · `list_exempt_uid` · `clear_exempt_uid`

**状态查询**：`status` · `status_root` · `status_log`

> `status` 会**先把当前调用方自动加入** hide_pid 与 exempt_uid，保证 UI 后续的 `list_*` 调用不被自己的 hook 拦截。
> 未命中任何命令时回显 `echo: <args>`。

**`status` 输出字段**（固定顺序，便于解析）：
`proc_hide` `file_hide` `comm_hide` `hide_pid_count` `hide_so_count` `hide_pkg_count` `hide_comm_count` `sys_exempt` `sys_exempt_uid_max` `log_enabled`

**`status_root` 输出字段**：
`root_hide` `file_hide` `root_file_hide` `root_kw_count` `exempt_uid_count`

---

## 模块枚举：GameKpm（game-kpm）

> 产物：`kpms/GameKpm/game-kpm.kpm` · 定位：**游戏运行期反检测**（针对腾讯 TerSafe + TPRT）

### 源文件职责

| 文件 | 职责 |
|---|---|
| [GameKpm.c](./kpms/GameKpm/GameKpm.c) | 入口；默认开启全部反检测开关；control0 分发（含 `SWITCH()` 宏批量生成 enable/disable） |
| [Common/Log.c](./kpms/GameKpm/Common/Log.c) | 独立 `[GAMEKPM]` 日志通道，`gk_log_enabled` 默认关 |
| [Common/Target.c](./kpms/GameKpm/Common/Target.c) | 三层目标判定；init 时解析并缓存 `__get_task_comm` / `task_tgid_nr` / `__task_pid_nr_ns` |
| [Common/Delegate.c](./kpms/GameKpm/Common/Delegate.c) | 解析 `module_control0` 并转发命令给 `kpm-svc`（未加载时只打日志不退出） |
| [Anti/AntiDebug.c](./kpms/GameKpm/Anti/AntiDebug.c) | 反调试四件套 + `__set_task_comm` / `write` 自动目标发现 |
| [Anti/AntiMem.c](./kpms/GameKpm/Anti/AntiMem.c) | mincore 全驻留谎报（上限 65536 页） |
| [Anti/AntiExec.c](./kpms/GameKpm/Anti/AntiExec.c) | execve 黑名单拦截 + inotify_add_watch 静默 |
| [Anti/AntiEnv.c](./kpms/GameKpm/Anti/AntiEnv.c) | `uname` 的 `release` / `version` 字段抹除内核特征 |
| [Anti/AntiPrivateDir.c](./kpms/GameKpm/Anti/AntiPrivateDir.c) | 只观测不拦截：记录游戏私有目录访问 |
| [Status/StatusFilter.c](./kpms/GameKpm/Status/StatusFilter.c) | `/proc/<pid>/status` 的 `TracerPid:` 改写为 0 |
| [PLAN.md](./kpms/GameKpm/PLAN.md) | 设计 / 与 inject-hide 的分工 / 实施步骤 |

### 目标进程三层判定

| 层 | 机制 | 触发 |
|---|---|---|
| 1. tgid 列表 | 用户态 `add_target_pid:` 显式注册 | `game_reload.sh` 启动游戏后自动注册 |
| 2. comm 前缀 | `task->comm` 前缀（默认种子 `com.tencent.tmg`、`MainThread-UE4`） | 命中后**自动加入 tgid 列表**（self-healing） |
| 3. fullname | 完整包名（默认种子 `com.tencent.tmgp.dfm`、`com.tencent.tmgp.pubgmhd`） | 由 `PR_SET_NAME` / `__set_task_comm` / `write(comm)` 自动发现 |

> 未注册任何目标时 `is_target_current()` 返回 0，所有 hook 透传 —— 开关开着也不会误伤其他进程。

### hook 表（共 11 个 hook 点）

| 模块 | hook 点 | 阶段 | 行为 |
|---|---|---|---|
| AntiDebug | `__NR_ptrace` | before | `PTRACE_TRACEME` / `PTRACE_ATTACH` / `PTRACE_SEIZE` → 直接返回 0（静默成功） |
| AntiDebug | `__NR_prctl` | before | `PR_SET_DUMPABLE` → 0；`PR_GET_DUMPABLE` → 1；`PR_SET_NAME` 命中 fullname → 注册 tgid |
| AntiDebug | `__NR_openat` | before | path 以 `/dev/pts/` 开头 → `-ENOENT` |
| AntiDebug | `__NR_write` | before | 长度门 [4,80] B → 命中 fullname → 注册 tgid（Android 14 comm 写路径） |
| AntiDebug | `__set_task_comm` | `hook_wrap3` before | zygote 改名即注册 tgid |
| AntiMem | `__NR_mincore` | after | `vec[]` 全填 1（页驻留全谎报） |
| AntiExec | `__NR_inotify_add_watch` | before | 短路，返回伪 wd `0x7FFE`，不真挂 |
| AntiExec | `__NR_execve` | before | basename 命中黑名单 → `-ENOENT` |
| AntiExec | `__NR_execveat` | before | 同上 |
| AntiEnv | `__NR_uname` | after | `UTS_RELEASE` / `UTS_VERSION` 抹除 `KernelPatch` / `dirty` 等特征 |
| AntiPrivateDir | `__NR_openat` | after | 仅记录 `/data/data|/data/user/0/com.tencent.tmgp.{dfm,pubgmhd}/…` 访问 |
| StatusFilter | `__NR_read` / `__NR_pread64` | after | 三串指纹（`Name:` + `Pid:` + `TracerPid:`）同时命中才把 `TracerPid` 改为 0 |

**execve 黑名单**：basename ∈ `su` `id` `mount` `getenforce` `getprop` `which` `busybox` `magisk` `ksud` `kpatch`；或完整路径 ∈ `/system/bin/su` `/system/xbin/su` `/sbin/su` `/system/bin/getprop` `/system/bin/getenforce`

**私有目录观测前缀**

| 路径前缀 | 标签 |
|---|---|
| `/data/data/com.tencent.tmgp.dfm/files/ano_tmp/` · `/data/user/0/…/ano_tmp/` | `dfm.ano`（TPRT 检测规则缓存） |
| `/data/data/com.tencent.tmgp.pubgmhd/files/ano_tmp/` · `/data/user/0/…/ano_tmp/` | `pmh.ano` |
| `…/files/` | `dfm.files` / `pmh.files` |
| `…/cache/` | `dfm.cache` / `pmh.cache`（TerSafe 临时数据） |

### control0 命令全集

> 统一调用格式：`kpatch <SUPERKEY> kpm ctl0 game-kpm <cmd>`

**一键预设**

| 命令 | 说明 |
|---|---|
| `preset_dfm` | 启用 8 项反检测 + 委托 `kpm-svc` 注册 DFM 隐藏关键词 |
| `preset_pubgmhd` | 同上，目标换为 PUBGMHD |

**目标列表**

| 命令 | 说明 |
|---|---|
| `add_target:<comm-prefix>` / `remove_target:<comm-prefix>` / `list_target` / `clear_target` | comm 前缀列表 |
| `add_target_pid:<tgid>` / `remove_target_pid:<tgid>` / `list_target_pid` / `clear_target_pid` | tgid 列表 |
| `add_target_full:<pkg>` / `remove_target_full:<pkg>` / `list_target_full` / `clear_target_full` | 完整包名列表 |

**反检测开关（成对 `enable_*` / `disable_*`）**

| 开关 | 对应能力 |
|---|---|
| `anti_ptrace` | ptrace 静默 |
| `anti_prctl` | PR_GET/SET_DUMPABLE 伪造 |
| `pts_block` | `/dev/pts/*` 拒绝 |
| `mincore_lie` | mincore 谎报 |
| `exec_block` | execve 黑名单 |
| `inotify_swallow` | inotify 静默 |
| `uname_spoof` | uname 改写 |
| `status_filter` | TracerPid 过滤 |
| `private_dir_watch` | 私有目录观测 |
| `log` | `[GAMEKPM]` 日志 |

> 共 **9 项功能开关 + 1 项日志开关**。init 时 9 项功能开关**全部默认开启**，`log` 默认关闭。

**其它**

| 命令 | 说明 |
|---|---|
| `status` | 输出全部开关值 + 三层目标列表统计与明细 |
| `delegate_test` | 向 `kpm-svc` 发 `list_hide_so`，验证 IPC 桥 |

### 辅助脚本

| 脚本 | 功能 |
|---|---|
| [tools/game_reload.sh](./kpms/GameKpm/tools/game_reload.sh) | ① unload 旧 game-kpm ② 确保 svc.kpm 已加载 ③ load game-kpm ④ 配置 inject-hide 隐藏关键词 ⑤ 启用 GameKpm 开关 ⑥ 启动游戏并轮询 leader 进程 → `add_target_pid` ⑦ 打印 status。superkey 解析顺序：`$SK` → `/data/local/tmp/.kp_key` → `/sdcard/kpkey.txt` → `/data/adb/kp/superkey` → `/data/adb/ap/superkey` → `/data/adb/.superkey` |
| [tools/auto_test.sh](./kpms/GameKpm/tools/auto_test.sh) | ① 本地 `make` ② `adb push` ③ 重装 KPM ④ 启动游戏（默认 DFM）⑤ 持续采样 logcat / dmesg / `ps` 存活 ⑥ 输出生还指标与触发的检测路径，日志落在 `GameKpm/test_runs/` |

---

## 模块枚举：demo 示例

| 模块 | 源码 | 演示内容 |
|---|---|---|
| demo-hello | [hello.c](./kpms/demo-hello/hello.c) | `KPM_NAME` / `KPM_INIT` / `KPM_CTL0` / `KPM_CTL1` / `KPM_EXIT` 最小闭环 + `compat_copy_to_user` 回显 |
| demo-inlinehook | [inlinehook.c](./kpms/demo-inlinehook/inlinehook.c) | 内核函数 inline hook（`hook_wrap` 系列） |
| demo-syscallhook | [syscallhook.c](./kpms/demo-syscallhook/syscallhook.c) | syscall hook（`fp_hook_syscalln`） |

---

## 基座枚举：KernelPatch

### kernel/base —— 内核运行时组件

| 文件 | 功能 |
|---|---|
| `setup.c` / `setup1.S` | 内核启动接管、早期环境搭建 |
| `start.c` / `start.h` | 启动主流程 |
| `cache.S` | cache 刷新（指令/数据一致性） |
| `map.c` / `map1.S` | 内核地址映射与页表 |
| `tlsf.c` / `tlsf.h` | TLSF 内核态内存分配器 |
| `hook.c` | ★ inline hook 框架：`hook/hook_wrap/unhook`、hook chain、trampoline |
| `fphook.c` | 函数指针 hook（`fp_hook_*`，用于 syscall 表） |
| `hotpatch.c` | 热补丁框架（`hotpatch_*`） |
| `hmem.c` | 物理/虚拟内存操作辅助 |
| `symbol.c` / `kallsyms` | 内核符号解析（无源码树场景） |
| `predata.c` | 预设数据段 |
| `baselib.c` | 无 libc 基础实现（`memcpy` 等） |
| `sha256.c` | 哈希（superkey 校验） |
| `log.c` | 早期日志 |

### kernel/patch —— 补丁与内核服务

| 文件 | 功能 |
|---|---|
| `patch.c` | 补丁主流程、SuperKey 校验、额外 item 嵌入 |
| `common/syscall.c` | 系统调用替换与 SuperCall 分发 |
| `common/supercall.c` | SuperCall 内核实现（hello/klog/ver/skey/su/kpm/kstorage…） |
| `common/supercmd.c` | SuperKey 命令行（`kpatch` 子命令） |
| `common/kstorage.c` | 内核态 key-value 存储（KPM 持久化） |
| `common/sucompat.c` | su 兼容层（UID 授权、SELinux 上下文） |
| `common/accctl.c` | 访问控制 / 白名单 |
| `common/secpass.c` | SELinux 绕过 |
| `common/sysname.c` | 系统名改写 |
| `common/taskob.c` | task 观察（凭据/task 结构访问） |
| `common/user_event.c` | 用户态事件 |
| `common/utils.c` / `test.c` | 工具函数 / 自检 |
| `module/module.c` | ★ KPM ELF 加载 / 卸载 / 元信息 / control0 调用 |
| `module/relo.c` | KPM ELF 重定位 |
| `module/insn.c` | ARM64 指令解析与重定位 |
| `ksyms/{libs,misc,task_cred,execv}.c` | 导出内核符号给 KPM 使用 |
| `android/*` | sepolicy 标志、userd、user_init 生成 |
| `include/uapi/scdefs.h` | SuperCall ABI 定义 |

### SuperCall 接口枚举

| 分类 | 调用号 |
|---|---|
| 探活 / 信息 | `SUPERCALL_HELLO` `0x1000`、`SUPERCALL_KLOG` `0x1004`、`SUPERCALL_BUILD_TIME` `0x1007`、`SUPERCALL_KERNELPATCH_VER` `0x1008`、`SUPERCALL_KERNEL_VER` `0x1009` |
| SuperKey | `SUPERCALL_SKEY_GET` `0x100a`、`SUPERCALL_SKEY_SET` `0x100b`、`SUPERCALL_SKEY_ROOT_ENABLE` `0x100c` |
| root | `SUPERCALL_SU` `0x1010`、`SUPERCALL_SU_TASK` `0x1011` |
| KPM | `SUPERCALL_KPM_LOAD` `0x1020`、`SUPERCALL_KPM_UNLOAD` `0x1021`、`SUPERCALL_KPM_CONTROL` `0x1022`、`SUPERCALL_KPM_NUMS` `0x1030`、`SUPERCALL_KPM_LIST` `0x1031`、`SUPERCALL_KPM_INFO` `0x1032` |
| kstorage | `SUPERCALL_KSTORAGE_ALLOC_GROUP` `0x1040`、`_WRITE` `0x1041`、`_READ` `0x1042`、`_LIST_IDS` `0x1043`、`_REMOVE` `0x1044`、`_REMOVE_GROUP` `0x1045` |
| 调试 | `SUPERCALL_BOOTLOG` `0x10fd`、`SUPERCALL_PANIC` `0x10fe`、`SUPERCALL_TEST` `0x10ff` |
| su 管理 | `SUPERCALL_SU_GRANT_UID` `0x1100`、`_REVOKE_UID` `0x1101`、`_NUMS` `0x1102`、`_LIST` `0x1103`、`_PROFILE` `0x1104`、`_GET/SET_ALLOW_SCTX` `0x1105/0x1106`、`_GET_PATH` `0x1110`、`_RESET_PATH` `0x1111`、`_GET_SAFEMODE` `0x1112` |

### hook API

| API | 用途 |
|---|---|
| `hook(func, replace, &backup)` / `unhook(func)` | 整体替换函数 |
| `hook_wrap0..12(func, before, after, udata)` | 保留原函数、按参数个数包 before/after |
| `hook_chain_add/remove`、`hook_chain_install/uninstall` | 多 hook 链式共存 |
| `fp_hook(fp_addr, replace, &backup)` / `fp_unhook` | 函数指针表 hook |
| `fp_hook_wrapN`、`fp_hook_syscalln`、`fp_unhook_syscalln` | syscall 级 hook（chain 语义，多模块不冲突） |
| `hook_fargs0..12_t` | before/after 回调参数结构（含 `skip_origin` / `ret` / `local` 数据槽） |

### tools / kptools —— 宿主机工具

| 文件 | 功能 |
|---|---|
| `image.c` | 内核镜像解析（boot.img / 二进制内核） |
| `kallsym.c` | 解析镜像内 kallsyms（无符号表时也能取符号偏移） |
| `patch.c` | 镜像打补丁（追加 kpimg、写 superkey、嵌入额外 item） |
| `kpm.c` | KPM 文件解析与校验 |
| `symbol.c` | ELF 符号处理 |
| `insn.c` | ARM64 指令解析（三态分支重定位） |
| `order.c` | 字节序 / 对齐辅助 |
| `kptools.c` | CLI 主入口 |
| `common.c` | 通用工具 |

**kptools 命令**：`-p/--patch`（打补丁/更新）、`-u/--unpatch`（去补丁）、`-r/--reset-skey`（重置 superkey）、`-d/--dump`（导出 kallsyms）、`-f/--flag`（导出 ikconfig）、`-l/--list`（列补丁信息）
**kptools 选项**：`-i` 镜像、`-k` kpimg、`-s`/`-S` superkey（`-S` 为可动态改的 root-superkey 哈希）、`-o` 输出、`-a` 附加键值、`-K` 嵌入 kpatch 二进制、`-M/-E/-T/-N/-V/-A/-D` 嵌入 extra item

### user / user_deprecated

| 目录 | 内容 |
|---|---|
| [user/](./user) | kuser ABI：`supercall.h`（手写，用户态嵌入用）。`kernel/Makefile` 的 `hdr` 目标会把 `kernel/patch/include/uapi/` → `user/uapi/`、`version` → `user/version`（两者均为生成物，已 gitignore） |
| [user_deprecated/](./user_deprecated) | 旧版用户态实现：`kpatch` CLI（`main.c`/`kpatch.c`）、`kpm.c/h`、`su.c`、`supercall.h`、Android 侧（`android_user.c`、`sumgr.c`、`apjni.cpp`）、CMake/Makefile。**只读，不在其中实现新功能** |

---

## 编译环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| OS | Linux x86_64 | Ubuntu / Debian / Arch 均可 |
| `make` | GNU Make | 标配 |
| ARM64 裸机 GCC | **必须 aarch64-none-elf-gcc**（不是 aarch64-linux-gnu-gcc） | 推荐 [arm GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) 13/14/15（CI 用 12.2.rel1） |
| Python 3 | ≥ 3.8 | 仅工具脚本 |
| zlib | `-lz` | kptools 链接依赖 |

> ⚠ **不能用 `aarch64-linux-gnu-gcc`** — 它生成的 ELF 带 glibc 依赖。KPM 必须用 *bare-metal* (`-elf-`) 工具链。

默认工具链路径（可通过 `TARGET_COMPILE` 环境变量覆盖）：
```
/home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf-
```

**设备端**：
- Android 13 / 14（其他版本未实测）
- root：APatch（推荐）或裸 KernelPatch
- 知道 `<SUPERKEY>` 字符串

---

## 编译步骤

```bash
# 1. 克隆
git clone https://github.com/18325984858/FrideHide-kpm.git
cd FrideHide-kpm

# 2. 编译两个 KPM
cd kpms/inject-hide && make && cd ../..
cd kpms/GameKpm    && make && cd ../..

# 3. 推送到设备
adb push kpms/inject-hide/svc.kpm    /sdcard/Download/
adb push kpms/GameKpm/game-kpm.kpm   /sdcard/Download/
```

工具链路径不一样：
```bash
make TARGET_COMPILE=/path/to/aarch64-none-elf-
```

**可选：编译基座与宿主机工具**

```bash
# kpimg（需 bare-metal 工具链）
cd kernel && export TARGET_COMPILE=aarch64-none-elf- && export ANDROID=1 && make

# kptools（宿主机，任选其一）
cd tools && make
# 或
cd tools && mkdir -p build && cd build && cmake .. && make
```

---

## 部署与加载

### 命令行（调试用）

```bash
KP=/data/data/me.bmax.apatch/patch/kpatch
SK=<SUPERKEY>

# 必须先装 inject-hide 再装 GameKpm
$KP $SK kpm load /sdcard/Download/svc.kpm
$KP $SK kpm load /sdcard/Download/game-kpm.kpm

# 配置 inject-hide 隐藏列表
$KP $SK kpm ctl0 kpm-svc add_hide_pkg:com.tencent.tmgp.dfm
$KP $SK kpm ctl0 kpm-svc enable_file_hide

# 启用 GameKpm 反检测
$KP $SK kpm ctl0 game-kpm preset_dfm
$KP $SK kpm ctl0 game-kpm enable_log

# 验证
$KP $SK kpm ctl0 game-kpm status
$KP $SK kpm ctl0 kpm-svc status
```

### 一键脚本

```bash
adb push kpms/GameKpm/tools/game_reload.sh /data/local/tmp/
adb shell "su -c 'sh /data/local/tmp/game_reload.sh dfm'"
# 或 pubgmhd
```

### Android 应用一键安装（推荐）

参见配套项目 [`game`](https://github.com/18325984858/game)：APK 内已 bundle `svc.kpm` + `game-kpm.kpm`，UI 一键安装。

---

## 使用说明

### 基本命令

| 操作 | 命令 |
|---|---|
| 列出已加载 KPM | `kpatch <SK> kpm list` |
| 模块详情 | `kpatch <SK> kpm info game-kpm` |
| 卸载 | `kpatch <SK> kpm unload game-kpm` |
| 发命令 | `kpatch <SK> kpm ctl0 <name> <cmd>` |

### 常用场景

#### 启用反作弊穿透
```bash
sh /data/local/tmp/game_reload.sh dfm
```

#### 仅启用某项 hook
```bash
$KP $SK kpm ctl0 game-kpm enable_anti_ptrace
$KP $SK kpm ctl0 game-kpm enable_status_filter
$KP $SK kpm ctl0 game-kpm enable_private_dir_watch
```

#### 隐藏自家工具的 SO
```bash
$KP $SK kpm ctl0 kpm-svc add_hide_so:libmytool
$KP $SK kpm ctl0 kpm-svc enable_file_hide
```

#### 注册目标进程（tgid 会变，建议用包名）
```bash
$KP $SK kpm ctl0 kpm-svc add_hide_pkg:com.tencent.tmgp.dfm   # 隐藏 + 自动注册 tgid
$KP $SK kpm ctl0 game-kpm add_target_pid:12345                # 显式注册
$KP $SK kpm ctl0 game-kpm list_target_pid                     # 查看
```

#### 自动化回归
```bash
adb push kpms/GameKpm/tools/auto_test.sh /data/local/tmp/
adb shell "su -c 'sh /data/local/tmp/auto_test.sh dfm 60'"
```

---

## 配套 Android 应用

[18325984858/game](https://github.com/18325984858/game) 提供：

- APK 内 bundle 两个 KPM（assets/svc.kpm + assets/game-kpm.kpm）
- 主界面"⚙ GameKpm 高级设置"折叠面板：9 项反检测开关 + 日志开关 + DFM/PUBG 一键预设 + 安装/卸载 KPM
- "💎 INJECT-HIDE 管理 (KPM)"页面：完整的 hide_so/hide_pkg/hide_comm 管理 + 安装/卸载
- gradle 自动同步：`./gradlew installDebug` → `make` 重编 KPM → 拷到 assets → 打 APK → 推到设备

---

## 稳定性 / 已知约束

### 已通过的测试
- ✅ DFM 60 秒冷启动 + 登录界面，0 闪退，0 panic
- ✅ KPM 装卸压测：40 轮反复 unload/load + ctl0，0 失败
- ✅ dobbyproject app 与两个 KPM 同时运行三方互不干扰

### 实测命中（DFM 60s 窗口）

| Hook | 命中 |
|---|---|
| prctl GET_DUMPABLE 伪造 | 3700+ 次 |
| mincore 谎报 | 70+ 次 |
| TracerPid 过滤 | 3+ 次 |
| 私有目录观测 | 44+ 条 |
| auto target_add_pid | 1 次 |

### 工程约束（避免再次踩坑）
1. KPM hook handler 在内核 IRQ-disabled / preemption-off 上下文跑，**绝不在 hot path 调 `kallsyms_lookup_name`** — 多核竞态会让 CPU 跳无效地址 → Oops（所有地址在 `*_install()` 里预解析缓存）
2. 高频路径（write / read 全集）不做内容解析；handler 局部变量 ≤ 64 字节
3. KP 的 hook chain 已消耗内核栈，叠加 KPM 自定义 hook 时谨防 stack overflow
4. 任何 syscall hook 在 system_server / pixelstats-vend / installd 等系统进程上也会触发，handler 必须**任何 task 上下文都安全**
5. KernelPatch 当前未导出 `module_control0` 给 KPM 间调用 — GameKpm → inject-hide 走 `Delegate` 软桥（失败仅打日志），实际编排在用户态 shell 串接
6. 目标锁定必须**幂等**：`target_add_pid` / `add_hide_pkg` 重复调用不会重复登记

### 反检测覆盖度（DFM/PUBGMHD）

| 检测路径 | 状态 |
|---|---|
| TPRT prctl GET_DUMPABLE 反调试 | ✅ 完全瘫痪 |
| TPRT mincore 页驻留探测 | ✅ 全谎报 |
| TPRT /proc/self/status TracerPid | ✅ 改 0 |
| TerSafe inotify 文件监控 | ✅ 静默 |
| TerSafe /dev/pts PTY 探测 | ✅ -ENOENT |
| TerSafe `sub_25B144` libc 直调表 | ✅ 走 syscall 层天然绕过 |
| TPRT `g_tprt_pfn_array` 互校 | ✅ 不在 user space hook libc |
| reveny Native Root Detector v7.7.0（mountinfo / 属性 / readlink） | ✅ `/debug_ramdisk` 整行丢弃 + 属性伪装 + readlink 过滤 |
| 系统属性 ro.boot.verifiedbootstate | ✅ 内核侧伪装（mmap 路径需 APM resetprop 配合） |
| PackageManager Binder 包列表检测 | ⚠ 内核侧无法过滤，需 Zygisk/LSPosed 用户态配合 |
| 硬件 Key Attestation | ⚠ 需 Tricky Store + keybox |

---

## 仓库自动化配置

`.github/` 同时承载 CI 与 Copilot 规范：

| 路径 | 说明 |
|---|---|
| [workflows/build.yml](./.github/workflows/build.yml) | 构建 kpimg（android + linux 两份）+ 3 个 demo KPM，按 `version` 生成 tag 并发布 Release |
| [workflows/build_dev.yml](./.github/workflows/build_dev.yml) | `dev` 分支 push / PR 构建（仅当 `kernel/` `user/` `tools/` `version` 变更时触发） |
| [ISSUE_TEMPLATE/](./.github/ISSUE_TEMPLATE) | `bug--can-t-boot.md` / `bug--patch-failed.md` / `feature_request.md` |
| [copilot-instructions.md](./.github/copilot-instructions.md) | Karpathy 风格编码准则（先想后写 / 最简实现 / 外科手术式改动 / 目标驱动） |
| [instructions/project-context.instructions.md](./.github/instructions/project-context.instructions.md) | 项目记忆：技术栈、目录约定、构建与热加载流程、已知陷阱 |
| [agents/](./.github/agents) · [chatmodes/](./.github/chatmodes) · [prompts/](./.github/prompts) | 自定义 agent / 模式 / 提示词 |

---

## 协议

- KernelPatch 上游：[bmax121/KernelPatch](https://github.com/bmax121/KernelPatch)
- License: GPL v2

仅供安全研究学习。**滥用本项目导致的封号 / 法律责任，作者概不承担**。
