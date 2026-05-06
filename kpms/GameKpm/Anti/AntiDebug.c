/*
 * 反调试 hook：
 *   - __NR_ptrace      : 目标进程 PTRACE_TRACEME / 自附加 → 静默成功
 *   - __NR_prctl       : 目标进程 PR_SET_DUMPABLE / PR_GET_DUMPABLE → 伪造
 *   - __NR_openat      : 目标进程 + path 命中 /dev/pts/ → -ENOENT
 */
#include "AntiDebug.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <ksyms.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>

#define PTRACE_TRACEME       0
#define PTRACE_ATTACH        16
#define PTRACE_SEIZE         0x4206

#define PR_SET_DUMPABLE      4
#define PR_GET_DUMPABLE      3
#define PR_SET_NAME          15

int g_anti_ptrace_enabled = 0;
int g_anti_prctl_enabled  = 0;
int g_pts_block_enabled   = 0;

static int hooked_ptrace = 0;
static int hooked_prctl  = 0;
static int hooked_openat = 0;
static int hooked_set_task_comm = 0;
static int hooked_write = 0;
static void *_set_task_comm_addr = 0;

/* __arch_copy_from_user — write hook 用 (任意二进制 buffer，不能用 strncpy) */
typedef unsigned long (*arch_copy_from_user_fn)(void *to, const void __user *from, unsigned long n);
static arch_copy_from_user_fn _arch_copy_from_user = 0;

/* task_tgid_nr 缓存 */
typedef int (*task_tgid_nr_fn)(void *task);
static task_tgid_nr_fn _task_tgid_nr = 0;

void anti_debug_set_ptrace(int enabled) { g_anti_ptrace_enabled = enabled ? 1 : 0; glog("anti_ptrace=%d", g_anti_ptrace_enabled); }
void anti_debug_set_prctl(int enabled)  { g_anti_prctl_enabled  = enabled ? 1 : 0; glog("anti_prctl=%d",  g_anti_prctl_enabled);  }
void anti_debug_set_pts(int enabled)    { g_pts_block_enabled   = enabled ? 1 : 0; glog("pts_block=%d",   g_pts_block_enabled);   }

static void before_ptrace(hook_fargs4_t *args, void *udata)
{
    if (!g_anti_ptrace_enabled) return;
    if (!is_target_current())   return;

    long request = (long)syscall_argn(args, 0);
    if (request == PTRACE_TRACEME) {
        glog_dbg("ptrace TRACEME swallowed");
        args->skip_origin = 1; args->ret = 0; return;
    }
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        glog_dbg("ptrace ATTACH/SEIZE swallowed (req=%ld)", request);
        args->skip_origin = 1; args->ret = 0; return;
    }
}

static void before_prctl(hook_fargs5_t *args, void *udata)
{
    long option = (long)syscall_argn(args, 0);

    /* PR_SET_NAME — 部分场景下游戏会调（pthread_setname_np 在新 bionic
       上走 /proc/<tid>/comm 写文件而非 prctl，所以这里命中率不高，但保留
       作为低成本的兜底自动检测路径）。 */
    if (option == PR_SET_NAME) {
        const char __user *uname = (const char __user *)syscall_argn(args, 1);
        if (uname) {
            char name[80];
            long n = compat_strncpy_from_user(name, uname, sizeof(name) - 1);
            if (n > 0) {
                name[sizeof(name) - 1] = '\0';
                if (is_target_fullname(name)) {
                    /* _task_tgid_nr 已在 anti_debug_install() 初始化时解析。
                       hot-path 中不再调 kallsyms_lookup_name（避免并发
                       读 half-set 指针 → CPU 跳无效地址 → Oops。） */
                    int tgid = -1;
                    if (_task_tgid_nr) tgid = _task_tgid_nr(current);
                    if (tgid > 0 && target_add_pid(tgid) == 0) {
                        glog_always("auto-detect via PR_SET_NAME: '%s' tgid=%d", name, tgid);
                    }
                }
            }
        }
        return;  /* 不短路 */
    }

    if (!g_anti_prctl_enabled) return;
    if (!is_target_current())  return;

    if (option == PR_SET_DUMPABLE) {
        glog_dbg("prctl SET_DUMPABLE swallowed");
        args->skip_origin = 1; args->ret = 0; return;
    }
    if (option == PR_GET_DUMPABLE) {
        glog_dbg("prctl GET_DUMPABLE → 1");
        args->skip_origin = 1; args->ret = 1; return;
    }
}

/*
 * before___set_task_comm(tsk, buf, exec)
 *   buf 是内核态字符串（zygote/Android Runtime 在 fork 出新 app 进程后直接调这个
 *   内核函数把 task->comm 写成完整包名，长度 ≤ 16 字节后被截断 — 但 Android
 *   实际写入的就是包名前 15 字节，例如 "com.tencent.tmg" 或完整短包名）。
 *
 *   我们用"包名前缀完全匹配 fullname 列表中任一项的前 15 字节"作为判定，命中即
 *   target_add_pid(tsk.tgid)。
 */
static void before___set_task_comm(hook_fargs3_t *args, void *udata)
{
    void *tsk = (void *)args->arg0;
    const char *buf = (const char *)args->arg1;
    if (!tsk || !buf || !buf[0]) return;

    /* buf 是内核态字符串可直接读。命中完整包名列表则注册 tgid。 */
    if (!is_target_fullname(buf)) return;

    /* _task_tgid_nr 已在 install 时解析，这里不重复查找 */
    int tgid = -1;
    if (_task_tgid_nr) tgid = _task_tgid_nr(tsk);
    if (tgid > 0 && target_add_pid(tgid) == 0) {
        glog_always("auto-detect via __set_task_comm: '%s' tgid=%d", buf, tgid);
    }
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    if (!g_pts_block_enabled) return;
    if (!is_target_current()) return;

    char path[64];
    const char __user *upath = (const char __user *)syscall_argn(args, 1);
    if (!upath) return;
    long n = compat_strncpy_from_user(path, upath, sizeof(path) - 1);
    if (n <= 0) return;
    path[n] = '\0';

    if (strncmp(path, "/dev/pts/", 9) == 0) {
        glog("openat blocked: %s", path);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

/*
 * before_write — 监听 /proc/<tid>/comm 改名事件
 *
 * Android 14 bionic 的 pthread_setname_np 不再走 prctl(PR_SET_NAME)，
 * 改成对 /proc/self/task/<tid>/comm 写入新名。Zygote 给 forked 出的
 * app 进程改名也走这条路径（写完整包名 com.tencent.tmgp.dfm）。
 *
 * 这是一个非常热的 syscall（每秒数千次），过滤必须极轻：
 *   1. 长度门：不在 [4, 80] 字节直接跳过
 *   2. 已是目标进程则跳过（避免日志反复刷）
 *   3. 否则只 copy 80 字节做精确/前缀匹配
 *   4. 不修改原 syscall 行为
 */
static void before_write(hook_fargs3_t *args, void *udata)
{
    /* 1. 长度门 */
    unsigned long count = (unsigned long)syscall_argn(args, 2);
    if (count < 4 || count > 80) return;

    /* 2. 已知目标 → 跳过（is_target_current 内部走 tgid 表，零拷贝） */
    if (is_target_current()) return;

    /* 3. 拷 buffer */
    if (!_arch_copy_from_user) return;
    const void __user *ubuf = (const void __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    char buf[81];
    if (_arch_copy_from_user(buf, ubuf, count) != 0) return;
    buf[count] = '\0';
    /* 去尾换行（comm 写法常含 \n） */
    if (count > 0 && buf[count - 1] == '\n') buf[count - 1] = '\0';

    /* 4. fullname 命中 → 注册 tgid */
    if (!is_target_fullname(buf)) return;

    /* _task_tgid_nr 已在 install 时解析，不重复查找 */
    int tgid = -1;
    if (_task_tgid_nr) tgid = _task_tgid_nr(current);
    if (tgid > 0 && target_add_pid(tgid) == 0) {
        glog_always("auto-detect via write(comm): '%s' tgid=%d", buf, tgid);
    }
}

int anti_debug_install(void)
{
    hook_err_t err;

    /* 在 install 时一次性解析所有内核符号指针，避免 hot-path lazy lookup
       导致并发读 half-set 函数指针 → CPU 跳无效地址 → Oops。 */
    if (!_task_tgid_nr) {
        _task_tgid_nr = (task_tgid_nr_fn)kallsyms_lookup_name("task_tgid_nr");
    }
    glog("init: _task_tgid_nr=%llx", (unsigned long long)_task_tgid_nr);

    err = fp_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    if (err) glog_err("hook __NR_ptrace failed: %d", err); else { hooked_ptrace = 1; glog("hook __NR_ptrace ok"); }

    err = fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    if (err) glog_err("hook __NR_prctl failed: %d", err); else { hooked_prctl = 1; glog("hook __NR_prctl ok"); }

    err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (err) glog_err("hook __NR_openat failed: %d", err); else { hooked_openat = 1; glog("hook __NR_openat ok"); }

    /* __set_task_comm hook 已禁用 — 实测在 Android 14 (UE4 直接写
       task->comm 内存) 上不命中 DFM/PUBGMHD leader 改名，且 hook
       内核函数会增加每次 syscall 的栈深度，可能与 KP 自身的 hook
       chain 叠加导致 "kernel stack overflow" panic。is_target_current
       的 comm 前缀路径已经能稳定捕获目标进程。 */
#if 0
    _set_task_comm_addr = (void *)kallsyms_lookup_name("__set_task_comm");
    if (_set_task_comm_addr) {
        err = hook_wrap3(_set_task_comm_addr, before___set_task_comm, 0, 0);
        if (err) glog_err("hook __set_task_comm failed: %d", err);
        else { hooked_set_task_comm = 1; glog("hook __set_task_comm ok"); }
    }
#endif

    /* __NR_write hook 已禁用 — write 是高频热路径（每秒数千次），
       每次 hook 都做 compat_strncpy_from_user(80 字节) 累加内核栈深度，
       与上面的 __set_task_comm 叠加触发了 "KP: kernel stack overflow"
       内核 panic 重启。实测新 bionic 也不走 write(/proc/comm) 改名路径，
       该 hook 对 DFM/PUBGMHD 无命中，纯负担。 */
#if 0
    _arch_copy_from_user = (arch_copy_from_user_fn)kallsyms_lookup_name("__arch_copy_from_user");
    if (_arch_copy_from_user) {
        err = fp_hook_syscalln(__NR_write, 3, before_write, 0, 0);
        if (err) glog_err("hook __NR_write failed: %d", err);
        else { hooked_write = 1; glog("hook __NR_write ok"); }
    }
#endif
    return 0;
}

void anti_debug_uninstall(void)
{
    if (hooked_ptrace) { fp_unhook_syscalln(__NR_ptrace, before_ptrace, 0); hooked_ptrace = 0; }
    if (hooked_prctl)  { fp_unhook_syscalln(__NR_prctl,  before_prctl,  0); hooked_prctl  = 0; }
    if (hooked_openat) { fp_unhook_syscalln(__NR_openat, before_openat, 0); hooked_openat = 0; }
    if (hooked_set_task_comm && _set_task_comm_addr) {
        hook_unwrap_remove(_set_task_comm_addr, before___set_task_comm, 0, 1);
        hooked_set_task_comm = 0;
    }
    if (hooked_write) { fp_unhook_syscalln(__NR_write, before_write, 0); hooked_write = 0; }
}
