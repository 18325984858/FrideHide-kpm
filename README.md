# FrideHide-kpm

> 基于 [KernelPatch](https://github.com/bmax121/KernelPatch) 的 Android 内核态隐藏 / 反检测 KPM 集合。
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

- [模块概览](#模块概览)
- [目录层次](#目录层次)
- [功能详解](#功能详解)
- [编译环境要求](#编译环境要求)
- [编译步骤](#编译步骤)
- [部署与加载](#部署与加载)
- [使用说明](#使用说明)
- [配套 Android 应用](#配套-android-应用)
- [稳定性 / 已知约束](#稳定性--已知约束)

---

## 模块概览

| 模块 | KPM 名 | 职责 | 体积 |
|---|---|---|---|
| inject-hide | `kpm-svc` | 通用隐藏：hide_pid / hide_so / hide_pkg / hide_comm / hide_root，过滤 maps/mountinfo/openat/read/execve/connect | ~92 KB |
| GameKpm | `game-kpm` | 游戏反作弊穿透：ptrace/prctl/openat-pts/mincore/inotify/uname/exec/status_filter + 私有目录访问观测 | ~62 KB |

两者**协同工作**：GameKpm 处理游戏专属反检测（TerSafe / TPRT），inject-hide 提供通用隐藏底座。

---

## 目录层次

```
FrideHide-kpm/
├── README.md
├── LICENSE                         GPL v2
├── kernel/                         KernelPatch 内核侧（patch + KPM 加载器）
│   ├── kpimg.lds  Makefile
│   ├── base/                       hook / hotpatch / kallsyms / pgtable
│   ├── include/                    KPM 公开头：hook.h / kpmodule.h / log.h ...
│   ├── linux/                      内核 UAPI / asm-generic / arch/arm64 子集
│   └── patch/                      模块加载、supercall、syscall 替换
├── kpms/                           ★ KPM 模块源码 ★
│   ├── demo-hello/                 最小示例
│   ├── demo-inlinehook/            inline hook 示例
│   ├── demo-syscallhook/           syscall hook 示例
│   ├── inject-hide/                ★ 通用隐藏 (kpm-svc)
│   │   ├── inject-hide.c           入口 + control0 命令分发
│   │   ├── Frid/FridHide.{c,h}     主 hook 实现
│   │   ├── Root/RootHide.{c,h}     Root 痕迹隐藏 (60+ 关键词)
│   │   ├── Config/Log.{c,h}        日志 + 配置
│   │   ├── Debug/                  调试辅助
│   │   ├── Struct/CStruct.h        内核结构偏移
│   │   ├── Makefile
│   │   └── svc.kpm                 (编译产物)
│   └── GameKpm/                    ★ 游戏反作弊 (game-kpm)
│       ├── GameKpm.c               入口 + 25+ control0 命令
│       ├── PLAN.md                 设计与实施计划
│       ├── Common/
│       │   ├── Log.{h,c}           独立 [GAMEKPM] 日志通道
│       │   ├── Target.{h,c}        目标判定 (comm 前缀 + tgid + fullname 三层)
│       │   └── Delegate.{h,c}      module_control0 IPC 桥
│       ├── Anti/
│       │   ├── AntiDebug.{h,c}     ptrace / prctl / openat(/dev/pts)
│       │   ├── AntiMem.{h,c}       mincore 谎报
│       │   ├── AntiExec.{h,c}      execve / inotify_add_watch
│       │   ├── AntiEnv.{h,c}       uname 改写
│       │   └── AntiPrivateDir.{h,c} 游戏私有目录访问观测
│       ├── Status/
│       │   └── StatusFilter.{h,c}  /proc/self/status TracerPid 过滤
│       ├── tools/
│       │   ├── game_reload.sh      一键卸载/加载/启动游戏/注册 tgid
│       │   └── auto_test.sh        自动化回归 (DFM/PUBGMHD 60s 生存)
│       ├── Makefile
│       └── game-kpm.kpm            (编译产物)
├── tools/                          (kpatch CLI 等用户态工具源码)
└── user/                           supercall / superkey 定义头
```

---

## 功能详解

### inject-hide (kpm-svc)

| 类别 | hook 点 | 行为 |
|---|---|---|
| /proc 文件过滤 | `show_map_vma` / `show_mountinfo` / `__get_task_comm` | maps / mountinfo 行隐藏 + 线程名擦写 |
| 路径访问拦截 | `__NR_openat / openat2 / faccessat / faccessat2 / readlinkat / newfstatat / statx` | 命中 hide_so / root_kw 关键词 → -ENOENT |
| 进程枚举过滤 | `__NR_getdents64` | /proc 目录扫到 hide_pid 子目录跳过 |
| 内容过滤 | `__NR_read / pread64` | 按 fd 路径分流：cmdline / mounts / status 行级删除/替换 |
| 子进程拦截 | `__NR_execve / execveat` | basename ∈ {su, magisk, ksud, getprop, ...} → -ENOENT |
| 网络 | `__NR_connect` | 屏蔽 frida-agent 27042 端口（adbd 例外） |
| Root 关键词种子 | 60+ | su / magisk / ksu / apatch / lsposed / shamiko / zygisk |
| 系统进程豁免 | `is_trusted_caller` | UID < 10000 + add_hide_pkg 自动注册 + dobbyproject 自家应用路径 |

**control0 命令**（通过 `kpatch <SK> kpm ctl0 kpm-svc <cmd>`）：
- `enable_/disable_<file_hide|comm_hide|sys_exempt|log|root_hide>`
- `add_/remove_/list_/clear_hide_<so|pid|pkg|comm>`
- `add_exempt_self / add_root_exempt_uid:<uid>`

### GameKpm (game-kpm)

针对**腾讯 TerSafe + TPRT** 反作弊栈（已分析 DFM / PUBGMHD 二进制）：

| 类别 | hook | 行为 |
|---|---|---|
| 反调试 | `__NR_ptrace` | 目标进程 PTRACE_TRACEME / 自附加 → 静默成功 |
| 反调试 | `__NR_prctl` | PR_SET_DUMPABLE → 0；PR_GET_DUMPABLE → 1 |
| 反调试 | `__NR_openat` | path 命中 `/dev/pts/*` → -ENOENT |
| 反内存探测 | `__NR_mincore` | vec[] 全填 1（页驻留全谎报） |
| 反子进程 | `__NR_execve / execveat` | basename ∈ 黑名单 → -ENOENT |
| 反文件监控 | `__NR_inotify_add_watch` | 返回伪 wd `0x7FFE` 不真挂 |
| 反环境指纹 | `__NR_uname` | release/version 抹除 KernelPatch / dirty |
| /proc 内容过滤 | `__NR_read / pread64` | 仅命中三串指纹（避免误伤） → TracerPid 改 0 |
| 私有目录观测 | `__NR_openat` after | 仅记录 `/data/data/com.tencent.tmgp.{dfm,pubgmhd}/files/...` 访问 |

**目标进程三层判定**：
1. tgid 列表 — 用户态主动注册
2. comm 前缀 — `com.tencent.tmg` / `MainThread-UE4`，命中后**自动加入 tgid 列表** self-healing
3. fullname 列表 — 完整包名（备用）

**control0 命令**：
- `preset_dfm` / `preset_pubgmhd` — 一键启用 8 类反检测开关
- `enable_/disable_<anti_ptrace|anti_prctl|pts_block|mincore_lie|exec_block|inotify_swallow|uname_spoof|status_filter|private_dir_watch|log>`
- `add_/list_/clear_target[_pid|_full]`
- `status` / `delegate_test`

---

## 编译环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| OS | Linux x86_64 | Ubuntu / Debian / Arch 均可 |
| `make` | GNU Make | 标配 |
| ARM64 裸机 GCC | **必须 aarch64-none-elf-gcc**（不是 aarch64-linux-gnu-gcc） | 推荐 [arm GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) 13/14/15 |
| Python 3 | ≥ 3.8 | 仅工具脚本 |

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

#### 自动化回归
```bash
adb push kpms/GameKpm/tools/auto_test.sh /data/local/tmp/
adb shell "su -c 'sh /data/local/tmp/auto_test.sh dfm 60'"
```

---

## 配套 Android 应用

[18325984858/game](https://github.com/18325984858/game) 提供：

- APK 内 bundle 两个 KPM（assets/svc.kpm + assets/game-kpm.kpm）
- 主界面"⚙ GameKpm 高级设置"折叠面板：10 个反检测开关 + DFM/PUBG 一键预设 + 安装/卸载 KPM
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
1. KPM hook handler 在内核 IRQ-disabled / preemption-off 上下文跑，**绝不在 hot path 调 `kallsyms_lookup_name`** — 多核竞态会让 CPU 跳无效地址 → Oops
2. 高频路径（write / read 全集）不做内容解析；handler 局部变量 ≤ 64 字节
3. KP 的 hook chain 已消耗内核栈，叠加 KPM 自定义 hook 时谨防 stack overflow
4. 任何 syscall hook 在 system_server / pixelstats-vend / installd 等系统进程上也会触发，handler 必须**任何 task 上下文都安全**
5. KernelPatch 当前未导出 `module_control0` — KPM 间通信走用户态 shell 串接

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
| 系统属性 ro.boot.verifiedbootstate | ⚠ 需 APM resetprop 配合 |
| 硬件 Key Attestation | ⚠ 需 Tricky Store + keybox |

---

## 协议

- KernelPatch 上游：[bmax121/KernelPatch](https://github.com/bmax121/KernelPatch)
- License: GPL v2

仅供安全研究学习。**滥用本项目导致的封号 / 法律责任，作者概不承担**。
