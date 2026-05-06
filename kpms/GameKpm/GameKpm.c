/*
 * @file   GameKpm.c
 * @brief  GameKpm — 游戏反检测专用 KPM 入口
 *
 * 职责：
 *   仅针对腾讯 TerSafe + TPRT 反作弊栈做内核态运行期反检测。
 *
 * 不做的事：
 *   通用 .so / 进程 / Root 关键词隐藏、frida 端口屏蔽、maps 过滤
 *   → 已在 inject-hide (kpm-svc) 实现，本模块通过 Delegate 桥调用。
 *
 * control0 命令：
 *   preset_dfm                          一键启用 DFM 反检测
 *   preset_pubgmhd                      一键启用 PUBGMHD 反检测
 *   add_target:<comm-prefix>            添加目标 comm 前缀（默认已加 com.tencent.tmg）
 *   remove_target:<comm-prefix>
 *   list_target
 *   clear_target
 *   enable_anti_ptrace / disable_anti_ptrace
 *   enable_anti_prctl  / disable_anti_prctl
 *   enable_pts_block   / disable_pts_block
 *   enable_mincore_lie / disable_mincore_lie
 *   enable_exec_block  / disable_exec_block
 *   enable_inotify_swallow / disable_inotify_swallow
 *   enable_uname_spoof / disable_uname_spoof
 *   enable_log / disable_log
 *   status                              输出所有开关 + 命中统计
 *   delegate_test                       发送 list_hide_so 给 kpm-svc 测桥接
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <kputils.h>

#include "Common/Log.h"
#include "Common/Target.h"
#include "Common/Delegate.h"
#include "Anti/AntiDebug.h"
#include "Anti/AntiMem.h"
#include "Anti/AntiExec.h"
#include "Anti/AntiEnv.h"
#include "Anti/AntiPrivateDir.h"
#include "Status/StatusFilter.h"

KPM_NAME("game-kpm");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("song");
KPM_DESCRIPTION("Anti-detection KPM for TerSafe/TPRT-protected games (DFM/PUBGMHD)");

/* ───── control0 用户态消息回写（沿用 inject-hide 的安全包装） ───── */
static void ctl_copy_out(char __user *out_msg, int outlen, const char *msg)
{
    if (!out_msg || outlen <= 0) return;
    if (!msg) msg = "";

    int n = 0;
    while (n < outlen - 1 && msg[n]) n++;
    if (n > 0) compat_copy_to_user(out_msg, msg, n);

    char nul = '\0';
    compat_copy_to_user(out_msg + n, &nul, 1);
}

/* 在本文件作用域里把 compat_copy_to_user 重写成自动带 outlen 的版本 */
#define compat_copy_to_user(dst, src, len) ctl_copy_out((dst), outlen, (const char *)(src))

/* ───── KPM init ───── */
static long game_kpm_init(const char *args, const char *event, void *__user reserved)
{
    glog_always("init, event=%s, args=%s", event ? event : "?", args ? args : "?");

    /* 1. 目标列表种子 */
    target_seed_defaults();

    /* 2. IPC 桥（即使 kpm-svc 没加载，这里只打日志，不退出） */
    delegate_init();

    /* 3. 安装 hook（默认全部不启用，等 control0 触发） */
    anti_debug_install();
    anti_mem_install();
    anti_exec_install();
    anti_env_install();
    anti_private_dir_install();
    status_filter_install();

    glog_always("installed");
    return 0;
}

/* ───── KPM exit ───── */
static long game_kpm_exit(void *__user reserved)
{
    glog_always("exit");
    anti_debug_uninstall();
    anti_mem_uninstall();
    anti_exec_uninstall();
    anti_env_uninstall();
    anti_private_dir_uninstall();
    status_filter_uninstall();
    return 0;
}

/* ───── control0 命令分发 ───── */
static long game_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) return -1;
    glog("control0: %s", args);

    /* preset 一键预设 */
    if (strncmp(args, "preset_dfm", 10) == 0) {
        delegate_preset_dfm();
        anti_debug_set_ptrace(1);
        anti_debug_set_prctl(1);
        anti_debug_set_pts(1);
        anti_mem_set_mincore(1);
        anti_exec_set_block(1);
        anti_exec_set_inotify(1);
        anti_env_set_uname(1);
        status_filter_set(1);
        char msg[] = "preset_dfm applied";
        compat_copy_to_user(out_msg, msg, sizeof(msg));
        return 0;
    }
    if (strncmp(args, "preset_pubgmhd", 14) == 0) {
        delegate_preset_pubgmhd();
        anti_debug_set_ptrace(1);
        anti_debug_set_prctl(1);
        anti_debug_set_pts(1);
        anti_mem_set_mincore(1);
        anti_exec_set_block(1);
        anti_exec_set_inotify(1);
        anti_env_set_uname(1);
        status_filter_set(1);
        char msg[] = "preset_pubgmhd applied";
        compat_copy_to_user(out_msg, msg, sizeof(msg));
        return 0;
    }

    /* 目标列表 */
    if (strncmp(args, "add_target:", 11) == 0) {
        int rc = target_add(args + 11);
        char buf[128];
        snprintf(buf, sizeof(buf), "add_target rc=%d total=%d", rc, target_count());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "remove_target:", 14) == 0) {
        int rc = target_remove(args + 14);
        char buf[128];
        snprintf(buf, sizeof(buf), "remove_target rc=%d total=%d", rc, target_count());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "list_target_pid", 15) == 0) {
        static char buf[1024];
        int off = snprintf(buf, sizeof(buf), "total=%d\n", target_count_pid());
        target_dump_pid(buf + off, sizeof(buf) - off);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "clear_target_pid", 16) == 0) {
        target_clear_pid();
        char msg[] = "target_pid cleared";
        compat_copy_to_user(out_msg, msg, sizeof(msg));
        return 0;
    }
    if (strncmp(args, "add_target_pid:", 15) == 0) {
        int pid = 0;
        const char *p = args + 15;
        while (*p >= '0' && *p <= '9') { pid = pid * 10 + (*p - '0'); p++; }
        int rc = target_add_pid(pid);
        char buf[128];
        snprintf(buf, sizeof(buf), "add_target_pid pid=%d rc=%d total=%d", pid, rc, target_count_pid());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "remove_target_pid:", 18) == 0) {
        int pid = 0;
        const char *p = args + 18;
        while (*p >= '0' && *p <= '9') { pid = pid * 10 + (*p - '0'); p++; }
        int rc = target_remove_pid(pid);
        char buf[128];
        snprintf(buf, sizeof(buf), "remove_target_pid pid=%d rc=%d total=%d", pid, rc, target_count_pid());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    /* 完整包名（精确匹配，PR_SET_NAME 路径） */
    if (strncmp(args, "list_target_full", 16) == 0) {
        static char buf[1024];
        int off = snprintf(buf, sizeof(buf), "total=%d\n", target_count_full());
        target_dump_full(buf + off, sizeof(buf) - off);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "clear_target_full", 17) == 0) {
        target_clear_full();
        char msg[] = "target_full cleared";
        compat_copy_to_user(out_msg, msg, sizeof(msg));
        return 0;
    }
    if (strncmp(args, "add_target_full:", 16) == 0) {
        int rc = target_add_full(args + 16);
        char buf[160];
        snprintf(buf, sizeof(buf), "add_target_full rc=%d total=%d", rc, target_count_full());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "remove_target_full:", 19) == 0) {
        int rc = target_remove_full(args + 19);
        char buf[160];
        snprintf(buf, sizeof(buf), "remove_target_full rc=%d total=%d", rc, target_count_full());
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "list_target", 11) == 0) {
        static char buf[1024];
        int off = snprintf(buf, sizeof(buf), "total=%d\n", target_count());
        target_dump(buf + off, sizeof(buf) - off);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (strncmp(args, "clear_target", 12) == 0) {
        target_clear();
        char msg[] = "target cleared";
        compat_copy_to_user(out_msg, msg, sizeof(msg));
        return 0;
    }

    /* 反检测开关（成对 enable/disable） */
    #define SWITCH(name, set_fn) \
        do { \
            if (strncmp(args, "enable_"  name, 7 + sizeof(name) - 1) == 0) { set_fn(1); char m[] = "enable_"  name; compat_copy_to_user(out_msg, m, sizeof(m)); return 0; } \
            if (strncmp(args, "disable_" name, 8 + sizeof(name) - 1) == 0) { set_fn(0); char m[] = "disable_" name; compat_copy_to_user(out_msg, m, sizeof(m)); return 0; } \
        } while (0)

    SWITCH("anti_ptrace",      anti_debug_set_ptrace);
    SWITCH("anti_prctl",       anti_debug_set_prctl);
    SWITCH("pts_block",        anti_debug_set_pts);
    SWITCH("mincore_lie",      anti_mem_set_mincore);
    SWITCH("exec_block",       anti_exec_set_block);
    SWITCH("inotify_swallow",  anti_exec_set_inotify);
    SWITCH("uname_spoof",      anti_env_set_uname);
    SWITCH("status_filter",    status_filter_set);
    SWITCH("private_dir_watch", anti_private_dir_set);
    SWITCH("log",              gk_log_set);

    #undef SWITCH

    /* status：输出所有开关与目标列表 */
    if (strncmp(args, "status", 6) == 0) {
        static char buf[2048];
        int off = snprintf(buf, sizeof(buf),
            "GameKpm status:\n"
            "  log              = %d\n"
            "  anti_ptrace      = %d\n"
            "  anti_prctl       = %d\n"
            "  pts_block        = %d\n"
            "  mincore_lie      = %d\n"
            "  exec_block       = %d\n"
            "  inotify_swallow  = %d\n"
            "  uname_spoof      = %d\n"
            "  status_filter    = %d\n"
            "  private_dir_watch= %d\n"
            "  targets comm     = %d\n",
            gk_log_enabled,
            g_anti_ptrace_enabled,
            g_anti_prctl_enabled,
            g_pts_block_enabled,
            g_mincore_lie_enabled,
            g_exec_block_enabled,
            g_inotify_swallow_enabled,
            g_uname_spoof_enabled,
            g_status_filter_enabled,
            g_private_dir_watch_enabled,
            target_count());
        off += target_dump(buf + off, sizeof(buf) - off);
        off += snprintf(buf + off, sizeof(buf) - off, "  targets pid      = %d\n", target_count_pid());
        off += target_dump_pid(buf + off, sizeof(buf) - off);
        off += snprintf(buf + off, sizeof(buf) - off, "  targets fullname = %d\n", target_count_full());
        target_dump_full(buf + off, sizeof(buf) - off);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    /* delegate_test：验证 IPC 桥 */
    if (strncmp(args, "delegate_test", 13) == 0) {
        long rc = delegate_svc("list_hide_so");
        char buf[64];
        snprintf(buf, sizeof(buf), "delegate_svc('list_hide_so') rc=%ld", rc);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    /* 默认回显 */
    char echo[128];
    snprintf(echo, sizeof(echo), "unknown: %s", args);
    compat_copy_to_user(out_msg, echo, strlen(echo) + 1);
    return 0;
}

KPM_INIT(game_kpm_init);
KPM_CTL0(game_kpm_control0);
KPM_EXIT(game_kpm_exit);
