/*
 * 反子进程 / 文件监控：
 *   - __NR_inotify_add_watch : 目标进程调用 → 返回伪 wd 不真挂监控
 *                              (anticheat-arch.md §3.7)
 *   - __NR_execve / execveat : 目标进程产生的 su / id / mount /
 *                              getenforce / getprop / which / busybox
 *                              直接拒绝 (anticheat-arch.md §3.3)
 */
#include "AntiExec.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>

int g_exec_block_enabled       = 0;
int g_inotify_swallow_enabled  = 0;
static int hooked_inotify = 0;
static int hooked_execve  = 0;
static int hooked_execveat= 0;

void anti_exec_set_block(int enabled)   { g_exec_block_enabled       = enabled ? 1 : 0; glog("exec_block=%d",       g_exec_block_enabled); }
void anti_exec_set_inotify(int enabled) { g_inotify_swallow_enabled  = enabled ? 1 : 0; glog("inotify_swallow=%d",  g_inotify_swallow_enabled); }

static const char *basename_of(const char *p)
{
    const char *s = p, *last = p;
    while (*s) { if (*s == '/') last = s + 1; s++; }
    return last;
}

static int is_blocked_exec(const char *path)
{
    const char *bn = basename_of(path);
    static const char *const blacklist[] = {
        "su", "id", "mount", "getenforce", "getprop",
        "which", "busybox", "magisk", "ksud", "kpatch",
        0,
    };
    for (int i = 0; blacklist[i]; i++) {
        if (strcmp(bn, blacklist[i]) == 0) return 1;
    }
    static const char *const path_blacklist[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/bin/getprop", "/system/bin/getenforce",
        0,
    };
    for (int i = 0; path_blacklist[i]; i++) {
        if (strcmp(path, path_blacklist[i]) == 0) return 1;
    }
    return 0;
}

static void before_inotify_add_watch(hook_fargs3_t *args, void *udata)
{
    if (!g_inotify_swallow_enabled) return;
    if (!is_target_current())       return;
    args->skip_origin = 1;
    args->ret = 0x7FFE;
    glog_dbg("inotify_add_watch swallowed");
}

static void before_execve(hook_fargs3_t *args, void *udata)
{
    if (!g_exec_block_enabled) return;
    if (!is_target_current())  return;

    char path[256];
    const char __user *upath = (const char __user *)syscall_argn(args, 0);
    if (!upath) return;
    long n = compat_strncpy_from_user(path, upath, sizeof(path) - 1);
    if (n <= 0) return;
    path[n] = '\0';

    if (is_blocked_exec(path)) {
        glog("execve blocked: %s", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

static void before_execveat(hook_fargs5_t *args, void *udata)
{
    if (!g_exec_block_enabled) return;
    if (!is_target_current())  return;

    char path[256];
    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    if (!upath) return;
    long n = compat_strncpy_from_user(path, upath, sizeof(path) - 1);
    if (n <= 0) return;
    path[n] = '\0';

    if (is_blocked_exec(path)) {
        glog("execveat blocked: %s", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

int anti_exec_install(void)
{
    hook_err_t err;

    err = fp_hook_syscalln(__NR_inotify_add_watch, 3, before_inotify_add_watch, 0, 0);
    if (err) { glog_err("hook __NR_inotify_add_watch failed: %d", err); }
    else     { hooked_inotify = 1; glog("hook __NR_inotify_add_watch ok"); }

    err = fp_hook_syscalln(__NR_execve, 3, before_execve, 0, 0);
    if (err) { glog_err("hook __NR_execve failed: %d", err); }
    else     { hooked_execve = 1; glog("hook __NR_execve ok"); }

    err = fp_hook_syscalln(__NR_execveat, 5, before_execveat, 0, 0);
    if (err) { glog_err("hook __NR_execveat failed: %d", err); }
    else     { hooked_execveat = 1; glog("hook __NR_execveat ok"); }

    return 0;
}

void anti_exec_uninstall(void)
{
    if (hooked_inotify)  { fp_unhook_syscalln(__NR_inotify_add_watch, before_inotify_add_watch, 0); hooked_inotify  = 0; }
    if (hooked_execve)   { fp_unhook_syscalln(__NR_execve,   before_execve,   0); hooked_execve   = 0; }
    if (hooked_execveat) { fp_unhook_syscalln(__NR_execveat, before_execveat, 0); hooked_execveat = 0; }
}
