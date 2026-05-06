/*
 * StatusFilter — /proc/<self>/status 内容过滤
 *
 * 检测点 (anticheat-arch.md §3.2)：TPRT 读 /proc/self/status 的
 * "TracerPid:" 行判断是否被附加；inject-hide 没在 read 路径过滤。
 *
 * 策略：
 *   1. 仅对目标进程 (is_target_current) 生效
 *   2. hook __NR_read / __NR_pread64 的 after-handler
 *   3. 对返回 buf 做"含特定 magic"扫描——只看 "TracerPid:"
 *   4. 命中后把数字 ASCII 改成 '0'，多余位补空格
 *
 * 这种"按内容判定"的方式比按 fd→path 反查代价低很多，并且 TracerPid
 * 这个串极少在非 status 文件中出现，误伤可忽略。
 */
#include "StatusFilter.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <ksyms.h>
#include <uapi/asm-generic/unistd.h>

int g_status_filter_enabled = 0;
static int hooked_read    = 0;
static int hooked_pread64 = 0;

static unsigned long (*_arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

void status_filter_set(int enabled)
{
    g_status_filter_enabled = enabled ? 1 : 0;
    glog("status_filter=%d", g_status_filter_enabled);
}

/* memmem: KP 没导出，自己写 */
static char *find_substr(char *hay, int hlen, const char *needle, int nlen)
{
    if (nlen == 0 || hlen < nlen) return 0;
    for (int i = 0; i <= hlen - nlen; i++) {
        int eq = 1;
        for (int j = 0; j < nlen; j++) {
            if (hay[i + j] != needle[j]) { eq = 0; break; }
        }
        if (eq) return hay + i;
    }
    return 0;
}

/*
 * 在 buf[0..len) 里查找 "TracerPid:" 行；命中则把"\t<digits>"改成"\t0"
 * 末尾用空格填充直到 '\n'，保持总长不变。
 */
static int rewrite_tracer_pid(char *buf, int len)
{
    static const char NEEDLE[] = "TracerPid:";
    char *p = find_substr(buf, len, NEEDLE, sizeof(NEEDLE) - 1);
    if (!p) return 0;

    /* 跳到行尾或 buf 尾 */
    char *line_start = p + sizeof(NEEDLE) - 1;
    char *q = line_start;
    while (q < buf + len && *q != '\n') q++;
    int line_len = (int)(q - line_start);
    if (line_len <= 0) return 0;

    /* 找第一个数字 */
    char *d = line_start;
    while (d < q && (*d == ' ' || *d == '\t')) d++;
    if (d >= q) return 0;
    if (*d < '0' || *d > '9') return 0;

    /* 把整段从第一个数字到行尾改成 "0" + 空格 */
    *d++ = '0';
    while (d < q) *d++ = ' ';
    return 1;
}

/*
 * /proc/<self>/stat 第 3 字段 state：被 ptrace 时是 't'，正常应是 'R'/'S'
 * 格式: "<pid> (<comm>) <state> <ppid> ..."
 *      把第 3 字段（'(...) ' 后的单字符）规范化为 'S'。
 */
static int rewrite_proc_stat_state(char *buf, int len)
{
    if (len < 8) return 0;
    /* 找最后一个 ')' — comm 内可能含 '(' '/'，但不会含 ')' */
    char *rp = 0;
    for (int i = len - 1; i >= 0; i--) {
        if (buf[i] == ')') { rp = buf + i; break; }
    }
    if (!rp || rp + 3 >= buf + len) return 0;
    if (rp[1] != ' ') return 0;
    char st = rp[2];
    /* 仅当处于 stopped/tracing/zombie 之类异常态时改写 */
    if (st == 't' || st == 'T' || st == 'Z' || st == 'X') {
        rp[2] = 'S';
        return 1;
    }
    return 0;
}

/*
 * /proc/<self>/wchan 内容若包含 "ptrace" / "do_signal" / "stop" / "tracehook"
 * 等被附加状态典型的 wchan，整个 buffer 改成 "0\n"+空格 padding
 */
static int rewrite_wchan(char *buf, int len)
{
    if (len <= 0) return 0;
    /* wchan 通常 < 64 字节，扫前 256 足够 */
    int scan = len < 256 ? len : 256;
    static const char *const bad[] = {
        "ptrace", "tracehook", "do_signal_stop", "do_jobctl_trap",
        "ptrace_stop", "schedule_timeout_killable",
        0
    };
    int hit = 0;
    for (int i = 0; bad[i]; i++) {
        int nlen = strlen(bad[i]);
        if (find_substr(buf, scan, bad[i], nlen)) { hit = 1; break; }
    }
    if (!hit) return 0;
    /* 改成 "0" + 后续空格（保持长度）+ 末尾换行（如果原本有） */
    int newline = (buf[len - 1] == '\n') ? 1 : 0;
    buf[0] = '0';
    for (int i = 1; i < len - newline; i++) buf[i] = ' ';
    if (newline) buf[len - 1] = '\n';
    return 1;
}

/*
 * /proc/<self>/syscall 内容显示当前 task 在哪条 syscall 上：
 *   "running\n"            (普通)
 *   "<nr> <args> <sp> <pc>" (sleeping/tracing)
 * 被 ptrace 时常见为 "61 ..." (wait4) 等. 一律改成 "running\n" + padding。
 */
static int rewrite_syscall_file(char *buf, int len)
{
    if (len < 4) return 0;
    /* 已经 "running" 开头 → 不动 */
    if (buf[0] == 'r' && buf[1] == 'u' && buf[2] == 'n') return 0;
    /* 仅当首字符是数字（被 syscall 卡住）时才改 */
    if (buf[0] < '0' || buf[0] > '9') return 0;
    static const char REPL[] = "running\n";
    int rl = sizeof(REPL) - 1;
    int n = rl < len ? rl : len;
    for (int i = 0; i < n; i++) buf[i] = REPL[i];
    for (int i = n; i < len; i++) buf[i] = ' ';
    if (buf[len - 1] != '\n') buf[len - 1] = '\n';
    return 1;
}

/*
 * 综合改写：返回是否有命中
 *
 * 重要安全约束：
 *   - 必须根据 buffer 内容指纹判定文件类型，而不是闭眼改任何 read 缓冲区
 *   - 误伤一次 → 系统级崩溃（内核态 hook 影响所有进程）
 *
 * 已抛弃的方案（曾导致设备崩溃）：
 *   ❌ 任何首字符为数字的 read → 改成 "running\n"  （/proc/uptime 等大量正常文件被毁）
 *   ❌ 任何 ')' 后第三字节是 't' 的 read → 改成 'S'  （误伤所有含 ')' 的文本）
 *   ❌ 任何含 "ptrace" 子串的 read → 全部清零      （logcat / dmesg dump 都会被毁）
 *
 * 当前策略：仅针对 /proc/<self>/status 的 TracerPid 行（极低误伤）
 * 其他 stat/wchan/syscall 过滤需要先做 fd→path 解析（待第 3 迭代）
 */
static int rewrite_status_buf(char *buf, int len)
{
    /* 必须是 /proc/<pid>/status 的内容才动手 — 用 "Name:" + "Pid:" + "TracerPid:"
       三个固定串同时出现作为指纹 */
    if (!find_substr(buf, len, "Name:", 5))      return 0;
    if (!find_substr(buf, len, "Pid:", 4))       return 0;
    if (!find_substr(buf, len, "TracerPid:", 10))return 0;

    return rewrite_tracer_pid(buf, len);
}

/*
 * after_read:
 *   args[1] = user buf；args[2] = count
 *   args->ret = bytes read（>0）
 */
static void after_read(hook_fargs3_t *args, void *udata)
{
    if (!g_status_filter_enabled) return;
    long n = (long)args->ret;
    if (n <= 4) return;
    if (!is_target_current()) return;
    if (!_arch_copy_from_user) return;

    void __user *ubuf = (void __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    /* 只扫前 4 KiB（status/stat/wchan/syscall 都远小于此）*/
    int cap = n < 4096 ? (int)n : 4096;
    static char kbuf[4096];
    if (_arch_copy_from_user(kbuf, ubuf, cap) != 0) return;
    if (!rewrite_status_buf(kbuf, cap)) return;

    (void)compat_copy_to_user(ubuf, kbuf, cap);
    glog_dbg("status filtered (read, n=%ld)", n);
}

static void after_pread64(hook_fargs4_t *args, void *udata)
{
    if (!g_status_filter_enabled) return;
    long n = (long)args->ret;
    if (n <= 4) return;
    if (!is_target_current()) return;
    if (!_arch_copy_from_user) return;

    void __user *ubuf = (void __user *)syscall_argn(args, 1);
    if (!ubuf) return;

    int cap = n < 4096 ? (int)n : 4096;
    static char kbuf[4096];
    if (_arch_copy_from_user(kbuf, ubuf, cap) != 0) return;
    if (!rewrite_status_buf(kbuf, cap)) return;

    (void)compat_copy_to_user(ubuf, kbuf, cap);
    glog_dbg("status filtered (pread64, n=%ld)", n);
}

int status_filter_install(void)
{
    _arch_copy_from_user = (typeof(_arch_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!_arch_copy_from_user) {
        glog_err("__arch_copy_from_user not found — status_filter disabled");
        return -1;
    }

    hook_err_t err;
    err = fp_hook_syscalln(__NR_read, 3, 0, after_read, 0);
    if (err) glog_err("hook __NR_read failed: %d", err); else { hooked_read = 1; glog("hook __NR_read ok"); }

    err = fp_hook_syscalln(__NR_pread64, 4, 0, after_pread64, 0);
    if (err) glog_err("hook __NR_pread64 failed: %d", err); else { hooked_pread64 = 1; glog("hook __NR_pread64 ok"); }
    return 0;
}

void status_filter_uninstall(void)
{
    if (hooked_read)    { fp_unhook_syscalln(__NR_read,    0, after_read);    hooked_read    = 0; }
    if (hooked_pread64) { fp_unhook_syscalln(__NR_pread64, 0, after_pread64); hooked_pread64 = 0; }
}
