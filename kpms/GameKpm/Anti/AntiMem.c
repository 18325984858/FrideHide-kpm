/*
 * 反内存探测：mincore 谎报全驻留
 *
 * 检测点 (anticheat-arch.md §3.4)：游戏调 mincore 探测页是否驻留，
 * 用作"是否被 Stalker / 全量内存读"的 indirect 指标。
 *
 * Hook 策略：after-handler 在 syscall 成功返回 0 时，把 user-space
 * 的 vec[] 全部填 1（页驻留）。
 *   __NR_mincore (3 args): start, len, vec
 */
#include "AntiMem.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/unistd.h>

#define PAGE_SIZE 4096

int g_mincore_lie_enabled = 0;
static int hooked = 0;

void anti_mem_set_mincore(int enabled)
{
    g_mincore_lie_enabled = enabled ? 1 : 0;
    glog("mincore_lie=%d", g_mincore_lie_enabled);
}

static void after_mincore(hook_fargs3_t *args, void *udata)
{
    if (!g_mincore_lie_enabled) return;
    if ((long)args->ret != 0)   return;       /* 让游戏自己处理失败 */
    if (!is_target_current())   return;

    unsigned long len = (unsigned long)syscall_argn(args, 1);
    void __user *vec  = (void __user *)syscall_argn(args, 2);
    if (!vec || len == 0) return;

    /* 页数 = ceil(len / PAGE_SIZE)，限制 64KiB */
    unsigned long pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if (pages > 65536) pages = 65536;

    static const char ones[256] = {
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    };

    unsigned long off = 0;
    while (off < pages) {
        int chunk = pages - off > sizeof(ones) ? (int)sizeof(ones) : (int)(pages - off);
        if (compat_copy_to_user((char __user *)vec + off, ones, chunk) < 0) break;
        off += chunk;
    }
    glog_dbg("mincore lied %lu pages", pages);
}

int anti_mem_install(void)
{
    hook_err_t err = fp_hook_syscalln(__NR_mincore, 3, 0, after_mincore, 0);
    if (err) { glog_err("hook __NR_mincore failed: %d", err); return -1; }
    hooked = 1;
    glog("hook __NR_mincore ok");
    return 0;
}

void anti_mem_uninstall(void)
{
    if (hooked) { fp_unhook_syscalln(__NR_mincore, 0, after_mincore); hooked = 0; }
}
