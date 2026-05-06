/*
 * AntiPrivateDir — 游戏私有目录访问监控（D 方案：观察 not 对抗）
 *
 * 设计原则：
 *   - 不修改任何系统调用行为
 *   - 不短路 syscall
 *   - 只在目标进程命中私有目录路径时打日志
 *   - 默认关闭，避免日志噪声；通过 control0 enable_private_dir_watch 打开
 *
 * 用途：观察 TerSafe / TPRT 在游戏私有目录里读/写哪些文件，为后续
 * 逆向 ano_tmp/74105212.xx.dat 等加密文件的访问模式提供数据。
 *
 * 性能：与 AntiDebug 的 before_openat 共用同一 syscall hook 链
 * （fp_hook_syscalln 是 chain，多 hook 不冲突）。
 */
#include "AntiPrivateDir.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/unistd.h>

int g_private_dir_watch_enabled = 0;
static int hooked = 0;

void anti_private_dir_set(int enabled)
{
    g_private_dir_watch_enabled = enabled ? 1 : 0;
    glog("private_dir_watch=%d", g_private_dir_watch_enabled);
}

/*
 * 关注路径前缀（顺序敏感 — 先匹配更具体的子路径以便详细日志）。
 * 这里只列了 DFM/PUBGMHD；要扩展只需加一行。
 */
struct prefix_entry {
    const char *prefix;
    const char *tag;     /* 简短标签便于日志区分 */
};

static const struct prefix_entry kWatchList[] = {
    /* 高价值 — TPRT 加密规则缓存 */
    { "/data/data/com.tencent.tmgp.dfm/files/ano_tmp/",       "dfm.ano" },
    { "/data/user/0/com.tencent.tmgp.dfm/files/ano_tmp/",     "dfm.ano" },
    { "/data/data/com.tencent.tmgp.pubgmhd/files/ano_tmp/",   "pmh.ano" },
    { "/data/user/0/com.tencent.tmgp.pubgmhd/files/ano_tmp/", "pmh.ano" },

    /* 中等 — TerSafe SDK 工作目录 */
    { "/data/data/com.tencent.tmgp.dfm/files/",       "dfm.files" },
    { "/data/data/com.tencent.tmgp.pubgmhd/files/",   "pmh.files" },

    /* 低 — 私有缓存 */
    { "/data/data/com.tencent.tmgp.dfm/cache/",       "dfm.cache" },
    { "/data/data/com.tencent.tmgp.pubgmhd/cache/",   "pmh.cache" },

    { 0, 0 }
};

static const char *match_watchlist(const char *path)
{
    for (int i = 0; kWatchList[i].prefix; i++) {
        int n = strlen(kWatchList[i].prefix);
        if (strncmp(path, kWatchList[i].prefix, n) == 0) {
            return kWatchList[i].tag;
        }
    }
    return 0;
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
    if (!g_private_dir_watch_enabled) return;
    if (!is_target_current())          return;

    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    if (!upath) return;

    char path[256];
    long n = compat_strncpy_from_user(path, upath, sizeof(path) - 1);
    if (n <= 0) return;
    path[sizeof(path) - 1] = '\0';

    /* 只处理绝对路径以减少噪声 */
    if (path[0] != '/') return;

    const char *tag = match_watchlist(path);
    if (!tag) return;

    int flags = (int)syscall_argn(args, 2);
    long ret = (long)args->ret;

    /* glog_dbg 受日志总开关控制，避免常态泛滥 */
    glog_dbg("[%s] openat='%s' flags=0x%x ret=%ld", tag, path, flags, ret);
}

int anti_private_dir_install(void)
{
    /* 注意：与 AntiDebug 的 before_openat 共用同一 __NR_openat
       hook chain。fp_hook_syscalln 内部支持 multi-hook，无冲突。 */
    hook_err_t err = fp_hook_syscalln(__NR_openat, 4, 0, after_openat, 0);
    if (err) {
        glog_err("hook __NR_openat(after) failed: %d", err);
        return -1;
    }
    hooked = 1;
    glog("hook __NR_openat(private_dir) ok");
    return 0;
}

void anti_private_dir_uninstall(void)
{
    if (hooked) {
        fp_unhook_syscalln(__NR_openat, 0, after_openat);
        hooked = 0;
    }
}
