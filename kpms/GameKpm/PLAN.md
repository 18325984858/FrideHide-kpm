# GameKpm — 游戏反检测专用 KPM

## 1. 项目定位

- **唯一职责**：针对 `com.tencent.tmgp.dfm`（三角洲行动）/ `com.tencent.tmgp.pubgmhd` 等使用 TerSafe + TPRT 反作弊栈的游戏，做 **游戏运行期检测项的内核态规避**。
- **不做**：通用文件/进程/SO 隐藏（这些已在 `kpm-svc`（inject-hide）里实现），通过 IPC 委托。
- **目标包名匹配**：`task->comm` 前缀命中 `com.tencent.tmgp.` 才生效，避免误伤其他 app。

## 2. 与 inject-hide 的分工

| 能力                                           | 归属        | 调用方式                                                  |
| ---------------------------------------------- | ----------- | --------------------------------------------------------- |
| 隐藏指定 .so 路径 / maps 行                    | `kpm-svc`   | `module_control0("kpm-svc", "add_hide_so:libfoo")`        |
| 隐藏指定包名 → 自动隐藏 PID                    | `kpm-svc`   | `module_control0("kpm-svc", "add_hide_pkg:com.x")`        |
| 擦写线程 comm                                  | `kpm-svc`   | `module_control0("kpm-svc", "add_hide_comm:gum-js-loop")` |
| 隐藏 root 关键词                               | `kpm-svc`   | 已默认开启 60+ 关键词                                     |
| frida 27042 端口屏蔽                           | `kpm-svc`   | `before_connect` 已实现                                   |
| **反 ptrace**                                  | **GameKpm** | hook `__NR_ptrace`                                        |
| **反 prctl(PR_SET_DUMPABLE)**                  | **GameKpm** | hook `__NR_prctl`                                         |
| **`/proc/self/status` TracerPid 过滤**         | **GameKpm** | hook `vfs_read` 或 `__NR_pread64`/`__NR_read`             |
| **`/proc/self/mounts(info)` 过滤**             | **GameKpm** | 同上                                                      |
| **`/dev/pts/*` 拒绝打开**                      | **GameKpm** | hook `__NR_openat`，仅对目标进程                          |
| **inotify_add_watch 静默**                     | **GameKpm** | hook `__NR_inotify_add_watch`                             |
| **mincore 谎报全驻留**                         | **GameKpm** | hook `__NR_mincore`                                       |
| **execve 拦截 su/id/mount/getenforce/getprop** | **GameKpm** | hook `__NR_execve`，仅对目标进程                          |
| **uname 改写**                                 | **GameKpm** | hook `__NR_uname`                                         |
| **getppid 伪造**                               | **GameKpm** | hook `__NR_getppid`（按需）                               |

## 3. 步骤清单（优先级从上到下）

### 第 1 阶段：骨架

- [x] 创建 `/home/song/Github/FrideHide-kpm/kpms/GameKpm/` 目录
- [ ] 写 `PLAN.md`（本文件）
- [ ] 写 `Makefile`（参考 inject-hide/Makefile）
- [ ] 写 `GameKpm.c` 模块入口（`KPM_NAME("game-kpm")` + `KPM_INIT/CTL0/EXIT`）
- [ ] 写 `Common/Delegate.{h,c}`：封装 `module_control0("kpm-svc", ...)` 桥接
- [ ] 写 `Common/Target.{h,c}`：判定"当前 task 是否目标包名"（用 `task->comm` 前缀比较 `com.tencent.tmgp.`）

### 第 2 阶段：control0 命令（用户态触发）

```
kpatch ctl game-kpm "preset_dfm"            # 一键启用所有反检测 + 委托 kpm-svc 添加隐藏关键词
kpatch ctl game-kpm "preset_pubgmhd"
kpatch ctl game-kpm "add_target:com.tencent.tmgp.dfm"
kpatch ctl game-kpm "remove_target:..."
kpatch ctl game-kpm "list_target"
kpatch ctl game-kpm "enable_anti_ptrace"
kpatch ctl game-kpm "enable_anti_prctl"
kpatch ctl game-kpm "enable_status_filter"
kpatch ctl game-kpm "enable_mounts_filter"
kpatch ctl game-kpm "enable_pts_block"
kpatch ctl game-kpm "enable_inotify_swallow"
kpatch ctl game-kpm "enable_mincore_lie"
kpatch ctl game-kpm "enable_exec_block"
kpatch ctl game-kpm "enable_uname_spoof"
kpatch ctl game-kpm "disable_*"             # 与上面成对
kpatch ctl game-kpm "status"                # 输出每个开关状态 + 命中计数
```

### 第 3 阶段：Hook 实现（按 anticheat-arch.md 8 大类对齐）

#### 3.1 反调试 (Anti/AntiDebug.c)

- [ ] hook `__NR_ptrace`：
  - 调用方是目标进程 + `request==PTRACE_TRACEME` → 直接返回 0（避免 TPRT 占位失败）
  - 调用方是目标进程 + `request==PTRACE_ATTACH/SEIZE` 且 `pid==自己` → 同样返回 0
  - 否则透传
- [ ] hook `__NR_prctl`：
  - 目标进程 + `option==PR_GET_DUMPABLE` → 返回 1
  - 目标进程 + `option==PR_SET_DUMPABLE` → 返回 0（伪成功）
- [ ] hook `__NR_openat`：
  - 目标进程 + path 匹配 `/dev/pts/` → 返回 -ENOENT

#### 3.2 /proc 内容过滤 (Status/StatusFilter.c)

- [ ] hook `__NR_read` / `__NR_pread64` / `__NR_readv`：
  - 检查 fd 对应的 dentry 路径是否为 `/proc/<self>/status` `/maps` `/mounts` `/mountinfo` `/cmdline` `/comm`
  - 命中后 `after_*` 阶段对返回的 buf 做行扫描：
    - `status`：`TracerPid:` 行替换数字为 `0`；`State:` 不动
    - `mounts/mountinfo`：跳过含 `magisk / apatch / ksu / data/adb / dobby` 的行（整行删除并向前压缩）
- [ ] 替代方案：直接 hook `vfs_read`，统一处理；优先用 syscall hook 简单稳妥

#### 3.3 反内存探测 (Anti/AntiMem.c)

- [ ] hook `__NR_mincore`：目标进程 → 把 vec 全填 1
- [ ] mprotect 不动（游戏自己的代码完整性会用到）

#### 3.4 反进程枚举 (Anti/AntiExec.c)

- [ ] hook `__NR_execve` / `__NR_execveat`：
  - 目标进程作为父进程 → 拦截 `argv[0]` 为 `su / id / mount / getenforce / getprop / which / busybox` → 返回 -ENOENT
- [ ] hook `__NR_inotify_add_watch`：目标进程 + path 在监控黑名单 → 返回伪 wd 不真挂

#### 3.5 反环境指纹 (Anti/AntiEnv.c)

- [ ] hook `__NR_uname`：目标进程 → 改写 `release/version` 去掉 `KernelPatch` `dirty` 等关键字

### 第 4 阶段：与 inject-hide 联动

- [ ] `Delegate.c` 实现：
  ```c
  long delegate_svc(const char *cmd);   // = module_control0("kpm-svc", cmd, NULL, 0)
  ```
- [ ] 在 `preset_dfm` / `preset_pubgmhd` 里调：
  ```c
  delegate_svc("add_hide_pkg:com.tencent.tmgp.dfm");
  delegate_svc("add_hide_comm:gum-js-loop");
  delegate_svc("add_hide_comm:gmain");
  delegate_svc("add_hide_comm:linjector");
  delegate_svc("add_hide_so:frida");
  delegate_svc("add_hide_so:gum");
  delegate_svc("enable_file_hide");
  ```
- [ ] 校验：先确保 `kpm-svc` 已 load，否则返回 `-ENOENT`，本模块只打日志不退出

### 第 5 阶段：测试与回归（现场设备已就绪）

- [ ] 编译：`make TARGET_COMPILE=/home/song/toolchains/arm-gcc-15/bin/aarch64-none-elf- KP_DIR=../..`
- [ ] adb push 到 `/sdcard/Download/game-kpm.kpm`
- [ ] kpatch load → kpatch ctl `preset_dfm`
- [ ] 启动 DFM，观察是否仍 `kill(getpid(),9)`
- [ ] 配合 KernelPatch + libpre.so（已在 game/ 工作区）做 IDA 回连验证：用 ida-pro-mcp 查 TerSafe `tss_sdk_init` 是否走到正常分支
- [ ] 配合 ida-pro-mcp-2 查 TPRT `sub_140428` 命中 prctl 后是否走到上报分支

## 4. 关键技术点

### 4.1 当前 task 判定目标

```c
// Common/Target.c
static const char TARGET_PREFIX[] = "com.tencent.tmgp.";
int is_target_task(void) {
    char comm[16];
    __get_task_comm(comm, sizeof(comm), current);
    return memcmp(comm, TARGET_PREFIX, sizeof(TARGET_PREFIX)-1) == 0;
}
```

注意：Android `task->comm` 只有 16 字节，包名超长会被截断 — 但 `com.tencent.tmgp.` 17 字节 > 16，需要改成更短前缀 `com.tencent.tmg`（15 字节 + \0）或维护精确的目标包名列表，建议后者。

### 4.2 调用 inject-hide 的安全边界

- `module_control0` 第 3 个参数是 `char __user *out_msg`。`kpm-svc` 内部对 `NULL/0` 是安全的（`ctl_copy_out` 检查了 `outlen<=0`）— 实测无问题
- 仍然推荐传一个内核态 buffer：用 `set_fs(KERNEL_DS)` + buf 把"用户态"骗过去（aarch64 5.x 之后 `uaccess_enable_privileged` / `force_uaccess_begin`）
- 实在不行就传 `NULL, 0` 让 `kpm-svc` 静默执行

### 4.3 read hook 的复杂度

- 直接 hook `__NR_read` 风险高 — 任何文件/socket 都会过这条路径。必须先在 hook handler 里用 `current->files->fdt[fd]->f_path` 解析路径，路径不在白名单立刻 return
- 性能：用 d_path() 在 fast path 太重；改为缓存"目标进程开过的 fd→是否敏感路径"的 per-task 小表

### 4.4 不能动的东西（动了游戏会自杀）

- TPRT `g_tprt_pfn_array` / `g_tprt_ori_array` 内部互校 → 不要在 user space hook libc
- TPRT `sub_BD1F8 settimeofday` 算术身份反 hook → 不要 hook `__NR_settimeofday`
- TPRT `sub_11A97C` RWX trampoline checksum → 不要碰游戏自己的 .text

## 5. 目录结构

```
GameKpm/
├── PLAN.md                    # 本文件
├── Makefile                   # 复用 inject-hide 模板
├── GameKpm.c                  # KPM 入口 + control0 命令分发
├── Common/
│   ├── Log.{h,c}              # 直接 #include ../inject-hide/Config/Log.h（或拷一份）
│   ├── Target.{h,c}           # 目标进程判定
│   └── Delegate.{h,c}         # module_control0 桥接 kpm-svc
├── Anti/
│   ├── AntiDebug.{h,c}        # ptrace / prctl / pts
│   ├── AntiMem.{h,c}          # mincore
│   ├── AntiExec.{h,c}         # execve / inotify
│   └── AntiEnv.{h,c}          # uname
└── Status/
    └── StatusFilter.{h,c}     # /proc/self/{status,mounts,mountinfo} 内容过滤
```

## 6. 待你拍板的决策点

1. **目标包名匹配策略**：用 16 字节 comm 前缀（不准确）还是 task→mm→exe_file 解析全名（准确但慢）？我倾向后者 + 缓存。
2. **control0 通信对外暴露**：是否需要也暴露一个 `kpatch ctl game-kpm "delegate:add_hide_so:libfoo"` 透传命令，让用户不用切换模块名？我倾向不暴露，保持职责单一。
3. **status/mounts 过滤**：要不要也过滤 `/proc/<pid>/maps`？现有 `kpm-svc` 已经在 `show_map_vma` 内核函数里过了；read 路径是用户直接读 `/proc/.../maps` 文件，走的是 `seq_read`，已被 `show_map_vma` 拦下 — 应该不需要再加。
4. **是否打包"游戏热重载脚本"**：写个 `tools/game_reload.sh` 一键 `kpatch unload + load + ctl preset_dfm`，方便调试。

确认后我开始落代码。
