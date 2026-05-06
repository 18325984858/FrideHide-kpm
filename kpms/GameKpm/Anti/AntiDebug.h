#ifndef GAMEKPM_ANTIDEBUG_H
#define GAMEKPM_ANTIDEBUG_H

/*
 * 反调试 hook：
 *   - __NR_ptrace      : 目标进程 PTRACE_TRACEME / 自附加 → 静默成功
 *   - __NR_prctl       : 目标进程 PR_SET_DUMPABLE / PR_GET_DUMPABLE → 伪造
 *   - __NR_openat      : 目标进程 + path 命中 /dev/pts/ 或 /proc/<pid>/status 黑名单 → 拒绝
 *
 * 全部受运行时开关控制，可独立开关。
 */

extern int g_anti_ptrace_enabled;
extern int g_anti_prctl_enabled;
extern int g_pts_block_enabled;

void anti_debug_set_ptrace(int enabled);
void anti_debug_set_prctl(int enabled);
void anti_debug_set_pts(int enabled);

int anti_debug_install(void);
void anti_debug_uninstall(void);

#endif /* GAMEKPM_ANTIDEBUG_H */
