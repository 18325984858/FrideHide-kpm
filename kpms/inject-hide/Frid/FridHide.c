/*
 * @file   Frid/FridHide.c
 * @brief  [svc] 的核心 hook 与隐藏列表实现。
 *
 * Hook 列表：
 *   - show_map_vma / show_smap_vma : 过滤 /proc/<pid>/maps|smaps 中命中关键词的行
 *   - __get_task_comm               : 擦写敏感线程名；同时匹配包名前缀自动把 tgid
 *                                     加入 hide_pid 并启用 proc_hide
 *   - sys_connect                   : 屏蔽非 adbd 对 127.0.0.1:27042 的 frida 链接
 *   - sys_openat / sys_faccessat    : 按 SO 关键字或隐藏 pid 的 /proc 路径拦截
 *   - sys_getdents64                : /proc 目录遍历时过滤掉被隐藏的 pid 子目录
 *
 * 运行时列表：
 *   - custom_hide_so[]   : SO 关键字（用于 maps 与路径隐藏）
 *   - custom_hide_pid[]  : 需要从 /proc 里消失的 pid
 *   - custom_hide_pkg[]  : 监控的包名（命中 comm 前缀自动隐藏其 tgid）
 *   - custom_hide_comm[] : 要擦空的线程名关键字
 *
 * 总开关：
 *   - file_hide_enabled / proc_hide_enabled / comm_hide_enabled
 */
#include "FridHide.h"
#include "../Config/Log.h"
#include "linux/pid.h"
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>  // struct task_struct 的完整定义在这里
#include <linux/cred.h>   // cred_offset (用于 UID 获取)
#include <asm/current.h>  // get_current() 的定义在这里
#include "syscall.h"
#include <kputils.h>
#include "../Root/RootHide.h"   // is_root_exempt_uid()

void *show_map_vma = 0;
void *show_mountinfo = 0;
void *show_vfsmnt = 0;
void *__system_property_get_sym = 0;
char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = 0;  // 为了后续能够调用，定义成函数指针变量
unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

int __get_task_comm_hook_status = 0;
int connect_hook_status = 0;
int openat_hook_status = 0;
int openat2_hook_status = 0;
int faccessat_hook_status = 0;
int faccessat2_hook_status = 0;
int getdents64_hook_status = 0;
int close_hook_status = 0;
int read_hook_status = 0;
int pread64_hook_status = 0;
int readlinkat_hook_status = 0;
int system_property_get_hook_status = 0;
void *show_smap_vma = 0;
int file_hide_enabled = 0;
int proc_hide_enabled = 1;  // PID 级隐藏总开关，默认开启（隐藏 PID 列表为空时不会拦截任何 /proc 访问）
int comm_hide_enabled = 1;  // 线程名隐藏总开关，默认开启
// ─────────────────────────────────────────────────────────────
//  系统进程豁免（sys_exempt）
//  启用后，UID < AID_APP_START (10000) 的调用方会被 is_trusted_caller()
//  视为可信，直接放行 openat/faccessat/getdents64 的路径级隐藏。
//  目的：避免隐藏 root/so 痕迹时误伤 installd/system_server/surfaceflinger
//        等系统进程，从而卡住 adb install / am start 等开发链路。
//  默认开启；运行时可通过 control0 "enable_sys_exempt" / "disable_sys_exempt"
//  切换。对应上限阈值可通过 "set_sys_exempt_uid:<N>" 调整。
// ─────────────────────────────────────────────────────────────
int sys_exempt_enabled = 1;
int sys_exempt_uid_max = 10000;  // Android AID_APP_START = 10000

// 自定义隐藏 SO 列表
static char custom_hide_so[HIDE_SO_MAX_COUNT][HIDE_SO_NAME_LEN];
static int custom_hide_so_count = 0;

// 自定义隐藏 PID 列表
static int custom_hide_pid[HIDE_PID_MAX_COUNT];
static int custom_hide_pid_count = 0;

int hide_so_add(const char *name)
{
    if (!name || strlen(name) == 0) return -1;
    if (custom_hide_so_count >= HIDE_SO_MAX_COUNT) {
        klog("hide_so_add: list full (%d)", HIDE_SO_MAX_COUNT);
        return -2;
    }
    // 检查是否已存在
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (strcmp(custom_hide_so[i], name) == 0) {
            klog("hide_so_add: '%s' already exists", name);
            return -3;
        }
    }
    strncpy(custom_hide_so[custom_hide_so_count], name, HIDE_SO_NAME_LEN - 1);
    custom_hide_so[custom_hide_so_count][HIDE_SO_NAME_LEN - 1] = '\0';
    custom_hide_so_count++;
    klog("hide_so_add: added '%s', total: %d", name, custom_hide_so_count);
    return 0;
}

int hide_so_remove(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (strcmp(custom_hide_so[i], name) == 0) {
            // 将最后一个移到当前位置
            if (i < custom_hide_so_count - 1) {
                memcpy(custom_hide_so[i], custom_hide_so[custom_hide_so_count - 1], HIDE_SO_NAME_LEN);
            }
            custom_hide_so[custom_hide_so_count - 1][0] = '\0';
            custom_hide_so_count--;
            klog("hide_so_remove: removed '%s', total: %d", name, custom_hide_so_count);
            return 0;
        }
    }
    klog("hide_so_remove: '%s' not found", name);
    return -2;
}

void hide_so_clear(void)
{
    for (int i = 0; i < custom_hide_so_count; i++) {
        custom_hide_so[i][0] = '\0';
    }
    custom_hide_so_count = 0;
    klog("hide_so_clear: cleared all");
}

int hide_so_count(void)
{
    return custom_hide_so_count;
}

int hide_so_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int offset = 0;
    for (int i = 0; i < custom_hide_so_count && offset < buf_len - 1; i++) {
        int n = snprintf(buf + offset, buf_len - offset, "%s\n", custom_hide_so[i]);
        if (n < 0 || n >= buf_len - offset) break;
        offset += n;
    }
    if (offset == 0 && buf_len > 0) {
        buf[0] = '\0';
    }
    return offset;
}

int is_custom_hidden_so(const char *str)
{
    if (!str) return 0;
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (strstr(str, custom_hide_so[i])) return 1;
    }
    return 0;
}

/* P0 扩展 hook handler 前向声明（实现位于本文件末尾） */
void before_newfstatat(hook_fargs4_t *args, void *udata);
void before_statx(hook_fargs5_t *args, void *udata);
void before_readlinkat(hook_fargs4_t *args, void *udata);
void after_readlinkat(hook_fargs4_t *args, void *udata);
void before_execve(hook_fargs4_t *args, void *udata);
void after_openat(hook_fargs4_t *args, void *udata);
void before_close(hook_fargs1_t *args, void *udata);
void before_faccessat2(hook_fargs4_t *args, void *udata);
void after_read(hook_fargs3_t *args, void *udata);
void after_pread64(hook_fargs4_t *args, void *udata);
void before_show_mount_seq(hook_fargs2_t *args, void *udata);
void after_show_mount_seq(hook_fargs2_t *args, void *udata);
void after_system_property_get(hook_fargs2_t *args, void *udata);

void frida_hide_install(void)
{
    klog("frida_hide_install");

    // 默认监控的包名（可随后通过 control0: add_hide_pkg / remove_hide_pkg 调整）
    hide_pkg_add("com.example.dobbyproject");

    // 默认隐藏的 SO 关键词（仅文件/maps 路径中真实存在的子串；
    // 纯线程名请放到下面的 hide_comm 列表，不要混进 hide_so）
    hide_so_add("libdobbyproject");
    hide_so_add("libdobby");
    hide_so_add("dobby");
    hide_so_add("frida-agent");
    hide_so_add("frida");

    // 默认隐藏的线程名 (comm) 关键词（可随后通过 control0 调整）
    hide_comm_add("gmain");
    hide_comm_add("gum-js-loop");
    hide_comm_add("GumJS");
    hide_comm_add("gdbus");
    hide_comm_add("pool-frida");
    hide_comm_add("linjector");

    show_map_vma = (void *) kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {

        klog("show_map_vma address: %llx", show_map_vma);

        int err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
    }

    show_smap_vma = (void *) kallsyms_lookup_name("show_smap_vma");
    if (show_smap_vma) {
        klog("show_smap_vma address: %llx", show_smap_vma);
        hook_wrap2(show_smap_vma, before_show_map_vma, after_show_map_vma, NULL);
    }

    show_mountinfo = (void *)kallsyms_lookup_name("show_mountinfo");
    if (show_mountinfo) {
        hook_err_t err = hook_wrap2(show_mountinfo, before_show_mount_seq, after_show_mount_seq, NULL);
        klog("show_mountinfo hook: %s", err ? "failed" : "success");
    }

    show_vfsmnt = (void *)kallsyms_lookup_name("show_vfsmnt");
    if (show_vfsmnt) {
        hook_err_t err = hook_wrap2(show_vfsmnt, before_show_mount_seq, after_show_mount_seq, NULL);
        klog("show_vfsmnt hook: %s", err ? "failed" : "success");
    }

  __get_task_comm = (void *) kallsyms_lookup_name("__get_task_comm");
    if (__get_task_comm) {
        hook_err_t err = hook_wrap3(__get_task_comm, 0, after_get_task_comm, 0);
        __get_task_comm_hook_status = err ? 0 : 1;
    }

    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if(__arch_copy_from_user && __get_task_comm) {
        hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, NULL);
        connect_hook_status = err ? 0 : 1;
    }

    // Hook openat to hide SO file from detection
    {
        hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, NULL);
        openat_hook_status = err ? 0 : 1;
        klog("openat hook: %s", openat_hook_status ? "success" : "failed");
    }

#ifdef __NR_openat2
    {
        hook_err_t err = fp_hook_syscalln(__NR_openat2, 4, before_openat, after_openat, NULL);
        openat2_hook_status = err ? 0 : 1;
        klog("openat2 hook: %s", openat2_hook_status ? "success" : "failed");
    }
#endif

    {
        hook_err_t err = fp_hook_syscalln(__NR_close, 1, before_close, 0, NULL);
        close_hook_status = err ? 0 : 1;
        klog("close hook: %s", close_hook_status ? "success" : "failed");
    }

    // Hook faccessat to prevent file existence check
    {
        hook_err_t err = fp_hook_syscalln(__NR_faccessat, 3, before_faccessat, 0, NULL);
        faccessat_hook_status = err ? 0 : 1;
        klog("faccessat hook: %s", faccessat_hook_status ? "success" : "failed");
    }

#ifdef __NR_faccessat2
    {
        hook_err_t err = fp_hook_syscalln(__NR_faccessat2, 4, before_faccessat2, 0, NULL);
        faccessat2_hook_status = err ? 0 : 1;
        klog("faccessat2 hook: %s", faccessat2_hook_status ? "success" : "failed");
    }
#endif

    // Hook getdents64 to filter /proc dirents for hidden PIDs (PID 级隐藏)
    {
        hook_err_t err = fp_hook_syscalln(__NR_getdents64, 3, 0, after_getdents64, NULL);
        getdents64_hook_status = err ? 0 : 1;
        klog("getdents64 hook: %s", getdents64_hook_status ? "success" : "failed");
    }

    {
        hook_err_t err = fp_hook_syscalln(__NR_read, 3, 0, after_read, NULL);
        read_hook_status = err ? 0 : 1;
        klog("read hook: %s", read_hook_status ? "success" : "failed");
    }

    {
        hook_err_t err = fp_hook_syscalln(__NR_pread64, 4, 0, after_pread64, NULL);
        pread64_hook_status = err ? 0 : 1;
        klog("pread64 hook: %s", pread64_hook_status ? "success" : "failed");
    }

    // ── P0 扩展 hook: stat 系列 + execve 系列 ──
    // 这些 hook 失败不影响主功能，所以只 klog 不更新 *_hook_status
    {
        /* __NR_newfstatat 在本头文件里靠 __ARCH_WANT_NEW_STAT 条件 #define，
         * 用无条件可见的 __NR3264_fstatat 替代（值同样为 79）。 */
        hook_err_t err = fp_hook_syscalln(__NR3264_fstatat, 4, before_newfstatat, 0, NULL);
        klog("newfstatat hook: %s", err ? "failed" : "success");
    }
    {
        hook_err_t err = fp_hook_syscalln(__NR_statx, 5, before_statx, 0, NULL);
        klog("statx hook: %s", err ? "failed" : "success");
    }
    {
        hook_err_t err = fp_hook_syscalln(__NR_readlinkat, 4, before_readlinkat, after_readlinkat, NULL);
        readlinkat_hook_status = err ? 0 : 1;
        klog("readlinkat hook: %s", readlinkat_hook_status ? "success" : "failed");
    }
    /* execve(filename, argv, envp) — path 在 arg0 → udata=0
     * execveat(dirfd, pathname, argv, envp, flags) — path 在 arg1 → udata=1 */
    {
        hook_err_t err = fp_hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
        klog("execve hook: %s", err ? "failed" : "success");
    }
    {
        hook_err_t err = fp_hook_syscalln(__NR_execveat, 5, before_execve, 0, (void *)1);
        klog("execveat hook: %s", err ? "failed" : "success");
    }

    __system_property_get_sym = (void *)kallsyms_lookup_name("__system_property_get");
    if (__system_property_get_sym) {
        hook_err_t err = hook_wrap2(__system_property_get_sym, 0, after_system_property_get, NULL);
        system_property_get_hook_status = err ? 0 : 1;
        klog("__system_property_get hook: %s", system_property_get_hook_status ? "success" : "failed");
    } else {
        klog("__system_property_get not found in kernel symbols; read-buffer property spoof remains active");
    }

}

void frida_hide_uninstall(void)
{
    klog("frida_hide_uninstall");
       if (show_map_vma) {
        unhook(show_map_vma);
        show_map_vma = 0;
    }

    if (show_smap_vma) {
        unhook(show_smap_vma);
        show_smap_vma = 0;
    }

    if (show_mountinfo) {
        unhook(show_mountinfo);
        show_mountinfo = 0;
    }

    if (show_vfsmnt) {
        unhook(show_vfsmnt);
        show_vfsmnt = 0;
    }

    if (__system_property_get_sym) {
        unhook(__system_property_get_sym);
        __system_property_get_sym = 0;
        system_property_get_hook_status = 0;
    }

  if (__get_task_comm) {
        unhook(__get_task_comm);
        __get_task_comm = 0;
        __get_task_comm_hook_status = 0;
    }

    if(connect_hook_status) {
        fp_unhook_syscalln(__NR_connect, before_connect, 0);
        connect_hook_status = 0;
    }

    if(openat_hook_status) {
        fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
        openat_hook_status = 0;
    }

#ifdef __NR_openat2
    if(openat2_hook_status) {
        fp_unhook_syscalln(__NR_openat2, before_openat, after_openat);
        openat2_hook_status = 0;
    }
#endif

    if(close_hook_status) {
        fp_unhook_syscalln(__NR_close, before_close, 0);
        close_hook_status = 0;
    }

    if(faccessat_hook_status) {
        fp_unhook_syscalln(__NR_faccessat, before_faccessat, 0);
        faccessat_hook_status = 0;
    }

#ifdef __NR_faccessat2
    if(faccessat2_hook_status) {
        fp_unhook_syscalln(__NR_faccessat2, before_faccessat2, 0);
        faccessat2_hook_status = 0;
    }
#endif

    if(getdents64_hook_status) {
        fp_unhook_syscalln(__NR_getdents64, 0, after_getdents64);
        getdents64_hook_status = 0;
    }

    if(read_hook_status) {
        fp_unhook_syscalln(__NR_read, 0, after_read);
        read_hook_status = 0;
    }

    if(pread64_hook_status) {
        fp_unhook_syscalln(__NR_pread64, 0, after_pread64);
        pread64_hook_status = 0;
    }

    /* P0 扩展 hook 的反卸载（无 status 标志，直接尝试 unhook） */
    fp_unhook_syscalln(__NR3264_fstatat, before_newfstatat, 0);
    fp_unhook_syscalln(__NR_statx,      before_statx,      0);
    if (readlinkat_hook_status) {
        fp_unhook_syscalln(__NR_readlinkat, before_readlinkat, after_readlinkat);
        readlinkat_hook_status = 0;
    }
    fp_unhook_syscalln(__NR_execve,     before_execve,     0);
    fp_unhook_syscalln(__NR_execveat,   before_execve,     0);

    file_hide_enabled = 0;
    proc_hide_enabled = 0;
    comm_hide_enabled = 0;
    hide_pkg_clear();
    hide_so_clear();
    hide_comm_clear();

}

// 内核环境下的 memmem 实现
static void *memmem_local(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return NULL;
    for (size_t i = 0; i <= haystacklen - needlelen; ++i) {
        if (memcmp((const char *)haystack + i, needle, needlelen) == 0)
            return (void *)((const char *)haystack + i);
    }
    return NULL;
}

// 检查 seq_file 缓冲区中是否包含敏感关键词（统一用 custom_hide_so[]）
static int is_hiden_module(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) return false;
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (memmem_local(m->buf, m->count, custom_hide_so[i], strlen(custom_hide_so[i])))
            return 1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────
//  线程名 (comm) 隐藏列表管理
// ─────────────────────────────────────────────────────────────
static char custom_hide_comm[HIDE_COMM_MAX_COUNT][HIDE_COMM_NAME_LEN];
static int  custom_hide_comm_count = 0;

int is_hiden_comm(const char *comm)
{
    if (!comm) return 0;
    if (!comm_hide_enabled) return 0;
    for (int i = 0; i < custom_hide_comm_count; i++) {
        if (custom_hide_comm[i][0] && strstr(comm, custom_hide_comm[i])) {
            return 1;
        }
    }
    return 0;
}

int hide_comm_add(const char *name)
{
    if (!name || !name[0]) return -1;
    if (custom_hide_comm_count >= HIDE_COMM_MAX_COUNT) return -2;
    for (int i = 0; i < custom_hide_comm_count; i++)
        if (strcmp(custom_hide_comm[i], name) == 0) return -3;
    strncpy(custom_hide_comm[custom_hide_comm_count], name, HIDE_COMM_NAME_LEN - 1);
    custom_hide_comm[custom_hide_comm_count][HIDE_COMM_NAME_LEN - 1] = '\0';
    custom_hide_comm_count++;
    klog("hide_comm_add: '%s', total: %d", name, custom_hide_comm_count);
    return 0;
}

int hide_comm_remove(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < custom_hide_comm_count; i++) {
        if (strcmp(custom_hide_comm[i], name) == 0) {
            if (i < custom_hide_comm_count - 1)
                memcpy(custom_hide_comm[i], custom_hide_comm[custom_hide_comm_count - 1], HIDE_COMM_NAME_LEN);
            custom_hide_comm[custom_hide_comm_count - 1][0] = '\0';
            custom_hide_comm_count--;
            klog("hide_comm_remove: '%s', total: %d", name, custom_hide_comm_count);
            return 0;
        }
    }
    return -2;
}

void hide_comm_clear(void)
{
    for (int i = 0; i < custom_hide_comm_count; i++) custom_hide_comm[i][0] = '\0';
    custom_hide_comm_count = 0;
    klog("hide_comm_clear");
}

int hide_comm_count(void) { return custom_hide_comm_count; }

int hide_comm_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < custom_hide_comm_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%s\n", custom_hide_comm[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

// ─────────────────────────────────────────────────────────────
//  包名级自动隐藏
//  - 运行时可增删查；默认种子为 com.example.dobbyproject。
//  - Linux task->comm 只有 16 字节（TASK_COMM_LEN=16，含 \0），
//    Android 的长包名会被截断，所以这里按"前 15 字节前缀"比较。
// ─────────────────────────────────────────────────────────────
#define TASK_COMM_CMP_LEN 15  // 16-1: 留给 '\0'

static char custom_hide_pkg[HIDE_PKG_MAX_COUNT][HIDE_PKG_NAME_LEN];
static int  custom_hide_pkg_count = 0;

int hide_pkg_add(const char *name)
{
    if (!name || !name[0]) return -1;
    if (custom_hide_pkg_count >= HIDE_PKG_MAX_COUNT) return -2;
    for (int i = 0; i < custom_hide_pkg_count; i++)
        if (strcmp(custom_hide_pkg[i], name) == 0) return -3;
    strncpy(custom_hide_pkg[custom_hide_pkg_count], name, HIDE_PKG_NAME_LEN - 1);
    custom_hide_pkg[custom_hide_pkg_count][HIDE_PKG_NAME_LEN - 1] = '\0';
    custom_hide_pkg_count++;
    klog("hide_pkg_add: '%s', total: %d", name, custom_hide_pkg_count);
    return 0;
}

int hide_pkg_remove(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < custom_hide_pkg_count; i++) {
        if (strcmp(custom_hide_pkg[i], name) == 0) {
            if (i < custom_hide_pkg_count - 1)
                memcpy(custom_hide_pkg[i], custom_hide_pkg[custom_hide_pkg_count - 1], HIDE_PKG_NAME_LEN);
            custom_hide_pkg[custom_hide_pkg_count - 1][0] = '\0';
            custom_hide_pkg_count--;
            klog("hide_pkg_remove: '%s', total: %d", name, custom_hide_pkg_count);
            return 0;
        }
    }
    return -2;
}

void hide_pkg_clear(void)
{
    for (int i = 0; i < custom_hide_pkg_count; i++) custom_hide_pkg[i][0] = '\0';
    custom_hide_pkg_count = 0;
    klog("hide_pkg_clear");
}

int hide_pkg_count(void) { return custom_hide_pkg_count; }

int hide_pkg_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < custom_hide_pkg_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%s\n", custom_hide_pkg[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

// 判断 task->comm（16 字节截断后）是否匹配任何已登记的包名前缀
int is_hidden_pkg_comm(const char *comm)
{
    if (!comm) return 0;
    // 取 comm 的实际长度（最多 15 字节，因为 task->comm 只有 16 字节带 \0）
    size_t clen = 0;
    while (clen < TASK_COMM_CMP_LEN && comm[clen]) clen++;
    if (clen == 0) return 0;
    for (int i = 0; i < custom_hide_pkg_count; i++) {
        size_t plen = strlen(custom_hide_pkg[i]);
        size_t cmp  = plen < TASK_COMM_CMP_LEN ? plen : TASK_COMM_CMP_LEN;
        if (clen < cmp) continue;                // comm 比前缀短则不可能匹配
        if (memcmp(comm, custom_hide_pkg[i], cmp) == 0) return 1;
    }
    return 0;
}

// 在当前 task_struct 内取出 tgid（pid_tgid helper 仅使用 current，
// 这里要取任意 tsk 的 tgid，所以直接读 offset）
static int task_struct_tgid(struct task_struct *tsk)
{
    if (!tsk || task_struct_offset.tgid_offset <= 0) return 0;
    return *(int *)((char *)tsk + task_struct_offset.tgid_offset);
}



void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    
    // 严谨检查：完善指针和缓冲区的合法性校验
    if (m && m->buf && (unsigned long)m->buf > 0xffffff0000000000) { 
        args->local.data0 = m->count;
    } 
}
void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    // 只有在 before 记录了合法的 data0 时才操作
    if (m && args->local.data0 < m->count && (unsigned long)m->buf > 0xffffff0000000000) {
        if (is_hiden_module(m)) {
             // 只有匹配时才打日志
             klog("[svc]: matched and hiding! ");
             m->count = (size_t)args->local.data0;
        }
    }
}

void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    struct task_struct *tsk = (struct task_struct *)args->arg2;
    if (comm && comm_buf_len) {
        // 命中已登记包名前缀 → 自动把该 tgid 加进 hide_pid 列表（幂等）
        if (is_hidden_pkg_comm(comm)) {
            int tgid = task_struct_tgid(tsk);
            if (tgid > 0 && !is_hidden_pid(tgid)) {
                if (hide_pid_add(tgid) == 0) {
                    proc_hide_enabled = 1;
                    klog("[svc]: auto-hide pkg '%s' tgid=%d", comm, tgid);
                }
            }
        }
        if (is_root_daemon_comm(comm)) {
            int tgid = task_struct_tgid(tsk);
            if (tgid > 0 && !is_hidden_pid(tgid)) {
                if (hide_pid_add(tgid) == 0) {
                    proc_hide_enabled = 1;
                    klog("[root_hide] auto-hide daemon '%s' tgid=%d", comm, tgid);
                }
            }
        }
        if (is_hiden_comm(comm)){
            pr_info("[svc]: get_task_comm hide -> %s\n", comm);
            size_t hide_len = strlen(comm);
            for(size_t i = 0; i < hide_len; i++) {
                comm[i] = ' ';
            }
        }
    }
}

// 网络协议中的端口号（大端）转换为主机字节序（小端）
u16 ntohs(u16 port) {
    return port >> 8 | port << 8;
}
void before_connect(hook_fargs3_t *args, void *udata) {
    struct sockaddr_in addr_kernel;
    const char __user *addr = (const char __user *)(unsigned long)syscall_argn(args, 1);
    if (!addr) return;

    __arch_copy_from_user(&addr_kernel, addr, sizeof(struct sockaddr_in));

    u16 port = ntohs(addr_kernel.sin_port);
    if (port == 27042) {
        char comm[16];
        __get_task_comm(comm, sizeof(comm), current);

        pr_warn("[svc]: connect to frida-agent, comm: %s, port: %d\n", comm, port);
        if (!strstr(comm, "adbd")) {  // 只允许 adbd 连接 frida
            pr_warn("[svc]: connect to frida-agent blocked, comm: %s, port: %d\n", comm, port);
            args->skip_origin = 1;  // 跳过原始的 connect 函数
            args->ret = -1;  // 返回 -1 表示拒绝连接
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  libdobbyproject.so 注入痕迹隐藏
// ═══════════════════════════════════════════════════════════════

// 检查文件路径是否包含需要隐藏的 SO 关键词（统一用 custom_hide_so[]）
static int is_hidden_path(const char *path)
{
    if (!path) return 0;
    return is_custom_hidden_so(path);
}

// ─────────────────────────────────────────────────────────────
//  PID 级隐藏 helpers
// ─────────────────────────────────────────────────────────────

// 查表
int is_hidden_pid(int pid)
{
    for (int i = 0; i < custom_hide_pid_count; i++)
        if (custom_hide_pid[i] == pid) return 1;
    return 0;
}

/* 前向声明：is_hidden_proc_path 需要查 current 的 pid/tgid */
static int current_pid_tgid(int *opid, int *otgid);

// 纯数字字符串 → PID → 是否隐藏
static int is_hidden_pid_str(const char *s, int len)
{
    if (!s || len <= 0 || len > 10) return 0;
    int v = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return 0;
        v = v * 10 + (c - '0');
        if (v > 0x7fffffff) return 0;
    }
    return is_hidden_pid(v);
}

// 路径是否形如 /proc/<hidden_pid>[/...] 或 /proc/self[/...]/proc/thread-self[/...]
// 自检（自己读自己 /proc/self）也要被遮，否则 App 自查 maps/status 仍能发现注入。
static int is_hidden_proc_path(const char *path)
{
    if (!path) return 0;
    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' ||
        path[3] != 'o' || path[4] != 'c' || path[5] != '/') return 0;
    const char *p = path + 6;

    /* /proc/self[/...]  → 当前 pid 是否在 hide_pid 名单 */
    if (p[0] == 's' && p[1] == 'e' && p[2] == 'l' && p[3] == 'f' &&
        (p[4] == '\0' || p[4] == '/')) {
        int pid = 0, tgid = 0;
        if (current_pid_tgid(&pid, &tgid) != 0) return 0;
        return is_hidden_pid(pid) || is_hidden_pid(tgid);
    }
    /* /proc/thread-self[/...]  → 同上 */
    if (memcmp(p, "thread-self", 11) == 0 && (p[11] == '\0' || p[11] == '/')) {
        int pid = 0, tgid = 0;
        if (current_pid_tgid(&pid, &tgid) != 0) return 0;
        return is_hidden_pid(pid) || is_hidden_pid(tgid);
    }

    /* /proc/<digits>[/...] */
    const char *start = p;
    while (*p >= '0' && *p <= '9') p++;
    if (p == start) return 0;
    if (*p != '\0' && *p != '/') return 0;
    return is_hidden_pid_str(start, (int)(p - start));
}

// 获取调用方 UID / PID，失败返回 -1
// 注意：非 static, 供 RootHide / inject-hide.c 中 control0 复用。
int current_uid_safe(void)
{
    struct task_struct *cur = current;
    if (!cur) return -1;
    if (task_struct_offset.cred_offset <= 0 || cred_offset.uid_offset <= 0) return -1;
    struct cred *c = *(struct cred **)((char *)cur + task_struct_offset.cred_offset);
    if (!c) return -1;
    return *(uid_t *)((char *)c + cred_offset.uid_offset);
}

static int current_pid_tgid(int *opid, int *otgid)
{
    struct task_struct *cur = current;
    if (!cur) return -1;
    if (task_struct_offset.pid_offset <= 0 || task_struct_offset.tgid_offset <= 0) return -1;
    if (opid)  *opid  = *(int *)((char *)cur + task_struct_offset.pid_offset);
    if (otgid) *otgid = *(int *)((char *)cur + task_struct_offset.tgid_offset);
    return 0;
}

/* 对外导出版本：供 inject-hide.c 在 add_hide_pkg 时自动豁免调用方使用 */
int current_pid_tgid_safe(int *opid, int *otgid)
{
    return current_pid_tgid(opid, otgid);
}

// 判断是否为"可信调用方"：
//   1. UID==0（su + dd/cat/base64 等 root 子进程）
//   2. PID/TGID 在隐藏列表中（reader app 自身）
//   3. 系统进程豁免启用时，UID < sys_exempt_uid_max（system/installd/
//      zygote/surfaceflinger 等系统 UID），避免 adb install/am start
//      等开发链路被误拦。
//   4. UID 在 RootHide exempt 名单中（自家 App 自我豁免，避免被
//      自己注入的 168 个 root 关键字误伤）。
//   5. task->comm 命中 RootHide 包名豁免（默认 me.bmax.apatch /
//      com.example.dobbyproject）。这是"零依赖应用层注册"的兜底，
//      解决 root_hide 启用后 popen-su 自伤导致 add_exempt_self
//      永远不发的死循环。
// 命中则 hook 放行，保证 mem_reader 端 & 系统管理链路工作不受影响。
static int is_trusted_caller(void)
{
    int uid = current_uid_safe();
    if (uid == 0) return 1;
    if (sys_exempt_enabled && uid > 0 && uid < sys_exempt_uid_max) return 1;
    if (is_root_exempt_uid(uid)) return 1;
    int pid = 0, tgid = 0;
    if (current_pid_tgid(&pid, &tgid) == 0) {
        if (is_hidden_pid(pid) || is_hidden_pid(tgid)) return 1;
    }
    /* 包名前缀豁免：通过 __get_task_comm 安全读取 current->comm。
     * __get_task_comm 在 install 时已通过 kallsyms 解析；为空时跳过。 */
    if (__get_task_comm) {
        char comm[16] = {0};
        __get_task_comm(comm, sizeof(comm), current);
        if (is_root_exempt_pkg_comm(comm)) return 1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────
//  P0 内容级隐藏：/proc 文本 fd 追踪 + read/pread64 输出过滤
// ─────────────────────────────────────────────────────────────
#define PROC_FD_TRACK_MAX 128
#define READ_FILTER_MAX   4096

enum proc_fd_filter_type {
    PROC_FD_NONE = 0,
    PROC_FD_TEXT = 1,
    PROC_FD_CMDLINE = 2,
    PROC_FD_PROPERTY_AREA = 3,
};

struct proc_fd_track_entry {
    int used;
    int tgid;
    int fd;
    int type;
};

static struct proc_fd_track_entry proc_fd_tracks[PROC_FD_TRACK_MAX];
static char read_filter_in[READ_FILTER_MAX];
static char read_filter_out[READ_FILTER_MAX];

static int current_tgid_only(void)
{
    int pid = 0, tgid = 0;
    if (current_pid_tgid(&pid, &tgid) != 0) return 0;
    return tgid;
}

static void proc_fd_track_add(int tgid, int fd, int type)
{
    if (tgid <= 0 || fd < 0 || type == PROC_FD_NONE) return;
    int free_idx = -1;
    for (int i = 0; i < PROC_FD_TRACK_MAX; i++) {
        if (proc_fd_tracks[i].used && proc_fd_tracks[i].tgid == tgid && proc_fd_tracks[i].fd == fd) {
            proc_fd_tracks[i].type = type;
            return;
        }
        if (!proc_fd_tracks[i].used && free_idx < 0) free_idx = i;
    }
    if (free_idx >= 0) {
        proc_fd_tracks[free_idx].used = 1;
        proc_fd_tracks[free_idx].tgid = tgid;
        proc_fd_tracks[free_idx].fd = fd;
        proc_fd_tracks[free_idx].type = type;
    }
}

static void proc_fd_track_remove(int tgid, int fd)
{
    if (tgid <= 0 || fd < 0) return;
    for (int i = 0; i < PROC_FD_TRACK_MAX; i++) {
        if (proc_fd_tracks[i].used && proc_fd_tracks[i].tgid == tgid && proc_fd_tracks[i].fd == fd) {
            proc_fd_tracks[i].used = 0;
            proc_fd_tracks[i].tgid = 0;
            proc_fd_tracks[i].fd = -1;
            proc_fd_tracks[i].type = PROC_FD_NONE;
        }
    }
}

static int proc_fd_track_type(int tgid, int fd)
{
    if (tgid <= 0 || fd < 0) return PROC_FD_NONE;
    for (int i = 0; i < PROC_FD_TRACK_MAX; i++) {
        if (proc_fd_tracks[i].used && proc_fd_tracks[i].tgid == tgid && proc_fd_tracks[i].fd == fd)
            return proc_fd_tracks[i].type;
    }
    return PROC_FD_NONE;
}

static int streq_n(const char *s, const char *lit, int n)
{
    int l = (int)strlen(lit);
    return n == l && memcmp(s, lit, l) == 0;
}

static int proc_content_path_type(const char *path)
{
    if (!path) return PROC_FD_NONE;
    if (strstr(path, "/dev/__properties__") || strstr(path, "/property_service/"))
        return PROC_FD_PROPERTY_AREA;
    if (strcmp(path, "/proc/mounts") == 0) return PROC_FD_TEXT;
    if (strcmp(path, "/proc/mountinfo") == 0) return PROC_FD_TEXT;

    if (memcmp(path, "/proc/", 6) != 0) return PROC_FD_NONE;
    const char *p = path + 6;
    if (memcmp(p, "self/", 5) == 0) {
        p += 5;
    } else if (memcmp(p, "thread-self/", 12) == 0) {
        p += 12;
    } else {
        const char *digits = p;
        while (*p >= '0' && *p <= '9') p++;
        if (p == digits || *p != '/') return PROC_FD_NONE;
        p++;
    }

    const char *file = p;
    while (*p && *p != '/') p++;
    int n = (int)(p - file);
    if (*p != '\0') return PROC_FD_NONE;

    if (streq_n(file, "cmdline", n)) return PROC_FD_CMDLINE;
    if (streq_n(file, "maps", n) || streq_n(file, "smaps", n) ||
        streq_n(file, "mountinfo", n) || streq_n(file, "mounts", n) ||
        streq_n(file, "status", n)) return PROC_FD_TEXT;
    return PROC_FD_NONE;
}

static int proc_link_path_type(const char *path)
{
    if (!path) return PROC_FD_NONE;
    if (memcmp(path, "/proc/", 6) != 0) return PROC_FD_NONE;
    const char *p = path + 6;
    if (memcmp(p, "self/", 5) == 0) {
        p += 5;
    } else if (memcmp(p, "thread-self/", 12) == 0) {
        p += 12;
    } else {
        const char *digits = p;
        while (*p >= '0' && *p <= '9') p++;
        if (p == digits || *p != '/') return PROC_FD_NONE;
        p++;
    }
    if (memcmp(p, "fd/", 3) == 0) return PROC_FD_TEXT;
    if (memcmp(p, "map_files/", 10) == 0) return PROC_FD_TEXT;
    if (strcmp(p, "exe") == 0) return PROC_FD_TEXT;
    return PROC_FD_NONE;
}

static int span_contains(const char *buf, int len, const char *needle)
{
    if (!buf || len <= 0 || !needle || !needle[0]) return 0;
    int nlen = (int)strlen(needle);
    return memmem_local(buf, len, needle, nlen) != 0;
}

static int sensitive_span_match(const char *buf, int len)
{
    if (!buf || len <= 0) return 0;
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (custom_hide_so[i][0] && span_contains(buf, len, custom_hide_so[i])) return 1;
    }
    for (int i = 0; i < custom_hide_comm_count; i++) {
        if (custom_hide_comm[i][0] && span_contains(buf, len, custom_hide_comm[i])) return 1;
    }
    if (is_root_content_match_n(buf, len)) return 1;
    return 0;
}

struct prop_spoof_item {
    const char *key;
    const char *value;
};

static const struct prop_spoof_item prop_spoofs[] = {
    {"ro.boot.verifiedbootstate", "green"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.boot.warranty_bit", "0"},
    {"ro.warranty_bit", "0"},
    {"ro.debuggable", "0"},
    {"ro.secure", "1"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.boot.selinux", "enforcing"},
    /* reveny Native Root Detector v7.7.0 “Bootloader Unlocked”
     * 第 2 条规则读 sys.oem_unlock_allowed。锁定设备上该属性
     * 通常不存在，读到任何值（包括 "0"）都会被它判定为 unlocked。
     * 改写为空字符串后，__system_property_get 返回长度 0，
     * 等价于属性不存在，绕过该条检测。 */
    {"sys.oem_unlock_allowed", ""},
    {"ro.oem_unlock_supported", "0"},
    {"ro.boot.realmebootstate", "green"},
    {"ro.boot.hwc", "GLOBAL"},
    {0, 0},
};

static const char *spoof_value_for_property(const char *name)
{
    if (!name) return 0;
    for (int i = 0; prop_spoofs[i].key; i++) {
        if (strcmp(name, prop_spoofs[i].key) == 0) return prop_spoofs[i].value;
    }
    return 0;
}

static int append_span(char *out, int cap, int off, const char *s, int len)
{
    if (!out || cap <= 0 || off < 0 || len < 0) return off;
    if (off >= cap - 1) return off;
    if (len > cap - 1 - off) len = cap - 1 - off;
    if (len > 0) memcpy(out + off, s, len);
    return off + len;
}

static int append_str(char *out, int cap, int off, const char *s)
{
    return append_span(out, cap, off, s, (int)strlen(s));
}

static int try_append_spoof_property_line(const char *line, int len, char *out, int cap, int off, int *changed)
{
    for (int i = 0; prop_spoofs[i].key; i++) {
        const char *key = prop_spoofs[i].key;
        const char *val = prop_spoofs[i].value;
        if (!span_contains(line, len, key)) continue;

        int bracket = (len > 0 && line[0] == '[');
        int eq = span_contains(line, len, "=");
        if (bracket) {
            off = append_str(out, cap, off, "[");
            off = append_str(out, cap, off, key);
            off = append_str(out, cap, off, "]: [");
            off = append_str(out, cap, off, val);
            off = append_str(out, cap, off, "]\n");
        } else if (eq) {
            off = append_str(out, cap, off, key);
            off = append_str(out, cap, off, "=");
            off = append_str(out, cap, off, val);
            off = append_str(out, cap, off, "\n");
        } else {
            off = append_str(out, cap, off, key);
            off = append_str(out, cap, off, ": ");
            off = append_str(out, cap, off, val);
            off = append_str(out, cap, off, "\n");
        }
        if (changed) *changed = 1;
        return off;
    }
    return -1;
}

static int filter_text_lines(const char *in, int len, char *out, int cap, int *changed, int drop_sensitive)
{
    int off = 0;
    int pos = 0;
    if (changed) *changed = 0;
    while (pos < len) {
        int start = pos;
        while (pos < len && in[pos] != '\n') pos++;
        if (pos < len && in[pos] == '\n') pos++;
        int line_len = pos - start;

        int prop_off = try_append_spoof_property_line(in + start, line_len, out, cap, off, changed);
        if (prop_off >= 0) {
            off = prop_off;
            continue;
        }
        if (drop_sensitive && sensitive_span_match(in + start, line_len)) {
            if (changed) *changed = 1;
            continue;
        }
        off = append_span(out, cap, off, in + start, line_len);
    }
    if (off < cap) out[off] = '\0';
    return off;
}

static int filter_cmdline(char *buf, int len)
{
    if (!buf || len <= 0) return 0;
    if (!sensitive_span_match(buf, len)) return 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] != '\0') buf[i] = ' ';
    }
    return 1;
}

static int filter_property_area_bytes(char *buf, int len)
{
    if (!buf || len <= 0) return 0;
    int changed = 0;
    for (int i = 0; prop_spoofs[i].key; i++) {
        const char *key = prop_spoofs[i].key;
        const char *val = prop_spoofs[i].value;
        int klen = (int)strlen(key);
        int vlen = (int)strlen(val);
        char *pos = memmem_local(buf, len, key, klen);
        while (pos) {
            int remain = len - (int)(pos - buf);
            int scan = remain > 192 ? 192 : remain;
            const char *bad_vals[] = {
                "orange", "yellow", "red", "unlocked", "userdebug",
                "eng", "test-keys", "permissive", "0", NULL
            };
            for (int j = 0; bad_vals[j]; j++) {
                const char *bad = bad_vals[j];
                int blen = (int)strlen(bad);
                char *vpos = memmem_local(pos, scan, bad, blen);
                if (!vpos) continue;
                if (vlen <= blen) {
                    memcpy(vpos, val, vlen);
                    if (blen > vlen) memset(vpos + vlen, 0, blen - vlen);
                    changed = 1;
                }
                break;
            }
            char *next = pos + klen;
            int next_len = len - (int)(next - buf);
            pos = next_len > 0 ? memmem_local(next, next_len, key, klen) : 0;
        }
    }
    return changed;
}

static void spoof_readlink_result(char __user *ubuf, unsigned long bufsiz, hook_fargs4_t *args)
{
    static const char spoof[] = "/dev/null";
    unsigned long n = sizeof(spoof) - 1;
    if (!ubuf || bufsiz == 0) return;
    if (n > bufsiz) n = bufsiz;
    if (compat_copy_to_user(ubuf, spoof, n) != 0) return;
    args->ret = (long)n;
}

static void filter_user_read_buffer(int fd, char __user *ubuf, long ret, int force_type, hook_fargs3_t *args3, hook_fargs4_t *args4)
{
    if (!ubuf || ret <= 0 || ret > READ_FILTER_MAX) return;
    if (!__arch_copy_from_user) return;
    if (is_trusted_caller()) return;

    int tgid = current_tgid_only();
    int type = force_type ? force_type : proc_fd_track_type(tgid, fd);
    int property_only = 0;
    if (type == PROC_FD_NONE) property_only = 1;

    if (__arch_copy_from_user(read_filter_in, ubuf, ret) != 0) return;
    int changed = 0;
    int out_len = (int)ret;

    if (type == PROC_FD_CMDLINE) {
        changed = filter_cmdline(read_filter_in, (int)ret);
        if (changed) memcpy(read_filter_out, read_filter_in, ret);
    } else if (type == PROC_FD_PROPERTY_AREA) {
        changed = filter_property_area_bytes(read_filter_in, (int)ret);
        if (changed) memcpy(read_filter_out, read_filter_in, ret);
    } else {
        out_len = filter_text_lines(read_filter_in, (int)ret, read_filter_out, READ_FILTER_MAX,
                        &changed, property_only ? 0 : 1);
        if (property_only && !changed) return;
    }

    if (!changed) return;
    if (out_len < 0) return;
    if (out_len > READ_FILTER_MAX) out_len = READ_FILTER_MAX;
    if (compat_copy_to_user(ubuf, read_filter_out, out_len) != 0) return;
    if (args3) args3->ret = out_len;
    if (args4) args4->ret = out_len;
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    int type = (int)args->local.data1;
    long fd = (long)args->ret;
    if (type != PROC_FD_NONE && fd >= 0) {
        proc_fd_track_add(current_tgid_only(), (int)fd, type);
    }
}

void before_close(hook_fargs1_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    proc_fd_track_remove(current_tgid_only(), fd);
}

void after_read(hook_fargs3_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    char __user *ubuf = (char __user *)(unsigned long)syscall_argn(args, 1);
    filter_user_read_buffer(fd, ubuf, (long)args->ret, PROC_FD_NONE, args, 0);
}

void after_pread64(hook_fargs4_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    char __user *ubuf = (char __user *)(unsigned long)syscall_argn(args, 1);
    filter_user_read_buffer(fd, ubuf, (long)args->ret, PROC_FD_NONE, 0, args);
}

void before_show_mount_seq(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    if (m && m->buf && (unsigned long)m->buf > 0xffffff0000000000) {
        args->local.data0 = m->count;
    }
}

void after_show_mount_seq(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (!m || !m->buf || (unsigned long)m->buf <= 0xffffff0000000000) return;
    if (is_trusted_caller()) return;
    size_t old = (size_t)args->local.data0;
    if (old >= m->count) return;
    if (sensitive_span_match(m->buf + old, (int)(m->count - old))) {
        m->count = old;
    }
}

void after_system_property_get(hook_fargs2_t *args, void *udata)
{
    if (is_trusted_caller()) return;
    const char *name = (const char *)args->arg0;
    char *value = (char *)args->arg1;
    const char *spoof = spoof_value_for_property(name);
    if (!spoof || !value) return;
    strncpy(value, spoof, 91);
    value[91] = '\0';
    args->ret = strlen(spoof);
}

static int before_path_common(const char __user *pathname, char *kpath, int kpath_len)
{
    if (!pathname || !kpath || kpath_len <= 1) return -1;
    long len = compat_strncpy_from_user(kpath, pathname, kpath_len - 1);
    if (len <= 0) return -1;
    kpath[len] = '\0';
    return 0;
}

static const char *path_basename_local(const char *path)
{
    const char *base = path;
    if (!path) return "";
    for (const char *cursor = path; *cursor; cursor++) {
        if (*cursor == '/') base = cursor + 1;
    }
    return base;
}

static int str_ends_with_local(const char *text, const char *suffix)
{
    if (!text || !suffix) return 0;
    size_t text_len = strlen(text);
    size_t suffix_len = strlen(suffix);
    if (text_len < suffix_len) return 0;
    return memcmp(text + text_len - suffix_len, suffix, suffix_len) == 0;
}

static int is_game_core_native_lib(const char *name)
{
    if (!name) return 0;
    return strcmp(name, "libdobbyproject.so") == 0 ||
           strcmp(name, "libdobby.so") == 0;
}

static int is_game_own_native_path(const char *path)
{
    if (!path) return 0;
    const char *base = path_basename_local(path);
    if (path[0] != '/' && is_game_core_native_lib(base)) return 1;
    if (!strstr(path, "/data/app/")) return 0;
    if (!strstr(path, "/com.example.dobbyproject")) return 0;
    if (!strstr(path, "/lib/arm64/")) return 0;
    return str_ends_with_local(base, ".so");
}

/*
 * dobbyproject 自家应用目录全豁免
 *
 * 原因：zygote 在 fork app 进程后、JNI_OnLoad 之前会读 APK 资源 + linker
 * 加载 SO，会涉及多种路径（.apk / lib/arm64 目录 / split_*.apk / base.apk!/...
 * zip 内路径 / data/user_de/<pkg>/cache/...）。这些都属于 dobbyproject
 * 自家应用，统一只要路径里含 "/com.example.dobbyproject" 就放行；
 * 不会泄露其它信息（只豁免自家应用目录里的 hide_so 命中）。
 *
 * 也覆盖：
 *   /data/app/~~xxx/com.example.dobbyproject-yyy/   (APK + lib + split)
 *   /data/data/com.example.dobbyproject/             (内部数据)
 *   /data/user/0/com.example.dobbyproject/           (multi-user 数据)
 *   /data/user_de/0/com.example.dobbyproject/        (Direct Boot 数据)
 *   /storage/emulated/0/Android/data/com.example.dobbyproject/  (外部数据)
 */
static int is_game_own_apk_path(const char *path)
{
    if (!path) return 0;
    if (strstr(path, "/com.example.dobbyproject")) return 1;
    return 0;
}

static int readlink_result_is_game_own_native_path(const char *buf, long len)
{
    if (!buf || len <= 0) return 0;
    char path[512];
    long copy_len = len;
    if (copy_len >= (long)sizeof(path)) copy_len = (long)sizeof(path) - 1;
    while (copy_len > 0) {
        char c = buf[copy_len - 1];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') break;
        copy_len--;
    }
    if (copy_len <= 0) return 0;
    memcpy(path, buf, copy_len);
    path[copy_len] = '\0';
    return is_game_own_native_path(path);
}

// openat(int dirfd, const char __user *pathname, int flags, mode_t mode) hook
// 拦截打开 dobby SO 文件的操作, 需要通过 control0 "enable_file_hide" 启用
void before_openat(hook_fargs4_t *args, void *udata)
{
    args->local.data1 = PROC_FD_NONE;
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (is_game_own_native_path(kpath) || is_game_own_apk_path(kpath)) return;

    if (!is_trusted_caller()) {
        args->local.data1 = proc_content_path_type(kpath);
    }

    // PID 级隐藏：拦截对 /proc/<hidden_pid>/... 的访问
    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller()) {
        klog("[svc]: blocking openat(proc) -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
        return;
    }

    if (!file_hide_enabled && !root_file_hide_enabled) return;

    int matched = (file_hide_enabled && is_hidden_path(kpath)) ||
                  (root_file_hide_enabled && is_root_kw_match(kpath));
    if (matched && !is_trusted_caller()) {
        klog("[svc]: blocking openat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// faccessat(int dirfd, const char __user *pathname, int mode) hook
// 拦截对 dobby SO 文件的存在性检查
void before_faccessat(hook_fargs3_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (is_game_own_native_path(kpath) || is_game_own_apk_path(kpath)) return;

    // PID 级隐藏
    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller()) {
        klog("[svc]: blocking faccessat(proc) -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
        return;
    }

    if (!file_hide_enabled && !root_file_hide_enabled) return;

    int matched = (file_hide_enabled && is_hidden_path(kpath)) ||
                  (root_file_hide_enabled && is_root_kw_match(kpath));
    if (matched && !is_trusted_caller()) {
        klog("[svc]: blocking faccessat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

void before_faccessat2(hook_fargs4_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (is_game_own_native_path(kpath) || is_game_own_apk_path(kpath)) return;

    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller()) {
        klog("[svc]: blocking faccessat2(proc) -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
        return;
    }

    if (!file_hide_enabled && !root_file_hide_enabled) return;

    int matched = (file_hide_enabled && is_hidden_path(kpath)) ||
                  (root_file_hide_enabled && is_root_kw_match(kpath));
    if (matched && !is_trusted_caller()) {
        klog("[svc]: blocking faccessat2 -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// ───────────────────────────────────────────────────────────────
//  P0 扩展 hook: stat 系列 + execve 系列
//
//  目的：openat/faccessat 只覆盖了"打开 / 存在性检查"两条入口；
//  实际 root 检测代码大量依赖：
//    * stat / lstat / newfstatat / statx —— 取 mode 判断文件存在
//    * readlinkat                        —— /proc/self/exe 判 magisk
//    * execve / execveat                 —— 直接 exec su / magisk / ksud
//  如果不覆盖这些 syscall, 即便 openat 全拦也会被绕过。
//
//  统一逻辑：
//    1. 拷贝 path 参数到内核栈
//    2. 命中 hide_pid /proc 路径 → 视 proc_hide_enabled 拦截
//    3. 命中 file_hide / root_file_hide 关键字 → 拦截
//    4. is_trusted_caller() 命中则放行（APatch、game、systemd uid 等）
//  返回值：syscall 通常返回 -ENOENT 表示文件不存在，是检测端最自然的"信号"。
// ───────────────────────────────────────────────────────────────

/* 通用 path 检查：1=拦截，0=放行；ret_errno 写入 args->ret */
static int hide_check_path(const char *kpath)
{
    if (!kpath) return 0;
    if (is_game_own_native_path(kpath) || is_game_own_apk_path(kpath)) return 0;
    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller())
        return 1;
    if (!file_hide_enabled && !root_file_hide_enabled) return 0;
    int matched = (file_hide_enabled && is_hidden_path(kpath)) ||
                  (root_file_hide_enabled && is_root_kw_match(kpath));
    if (matched && !is_trusted_caller()) return 1;
    return 0;
}

/* newfstatat(int dirfd, const char __user *path, struct stat __user *st, int flag)
 * statx(int dfd, const char __user *path, int flags, unsigned mask,
 *       struct statx __user *buffer)
 * 两者 path 都在 arg1。 */
void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (hide_check_path(kpath)) {
        klog("[svc]: blocking stat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

void before_statx(hook_fargs5_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (hide_check_path(kpath)) {
        klog("[svc]: blocking statx -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

/* readlinkat(int dirfd, const char __user *path, char __user *buf, size_t)
 * 主要用来挡 readlinkat(/proc/self/exe) / readlinkat(/proc/<pid>/exe) 反查。 */
void before_readlinkat(hook_fargs4_t *args, void *udata)
{
    args->local.data1 = PROC_FD_NONE;
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    char kpath[256];
    if (before_path_common(pathname, kpath, sizeof(kpath)) != 0) return;
    if (!is_trusted_caller()) args->local.data1 = proc_link_path_type(kpath);
    if (hide_check_path(kpath)) {
        klog("[svc]: blocking readlinkat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

void after_readlinkat(hook_fargs4_t *args, void *udata)
{
    long ret = (long)args->ret;
    if (ret <= 0 || ret > READ_FILTER_MAX) return;
    if (is_trusted_caller()) return;
    char __user *ubuf = (char __user *)(unsigned long)syscall_argn(args, 2);
    unsigned long bufsiz = (unsigned long)syscall_argn(args, 3);
    if (!ubuf || bufsiz == 0 || !__arch_copy_from_user) return;
    if (__arch_copy_from_user(read_filter_in, ubuf, ret) != 0) return;
    if (readlink_result_is_game_own_native_path(read_filter_in, ret)) return;
    if ((int)args->local.data1 != PROC_FD_NONE || sensitive_span_match(read_filter_in, (int)ret)) {
        if (sensitive_span_match(read_filter_in, (int)ret)) {
            spoof_readlink_result(ubuf, bufsiz, args);
        }
    }
}

/* execve(const char __user *filename, ...)
 * execveat(int dirfd, const char __user *pathname, ...)
 *  - execve  : path 在 arg0
 *  - execveat: path 在 arg1
 *  hook 时通过 udata 区分（注册时传 0 / 1）。
 *
 *  设计：仅当 root_file_hide_enabled 命中时才拦，避免 dobby/file_hide
 *  把普通 App 业务命令一并干掉。is_trusted_caller 仍然放行（APatch /
 *  game 自身要能 exec su 拿 superkey）。 */
void before_execve(hook_fargs4_t *args, void *udata)
{
    int path_arg = (udata == (void *)1) ? 1 : 0;
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, path_arg);
    if (!pathname) return;
    char kpath[256];
    long len = compat_strncpy_from_user(kpath, pathname, sizeof(kpath) - 1);
    if (len <= 0) return;
    kpath[len] = '\0';

    /* 仅 root 关键词命中时拦截，且 trusted caller 放行 */
    if (!root_file_hide_enabled) return;
    if (!is_root_kw_match(kpath)) return;
    if (is_trusted_caller()) return;

    klog("[svc]: blocking execve -> %s", kpath);
    args->skip_origin = 1;
    args->ret = -ENOENT;
}

// 供外部调用: 启用/禁用文件级隐藏
void dobby_hide_set_file_hide(int enabled)
{
    file_hide_enabled = enabled;
    klog("[svc]: file_hide_enabled = %d", enabled);
}

// ═══════════════════════════════════════════════════════════════
//  PID 级隐藏：getdents64 过滤 + PID 列表管理
// ═══════════════════════════════════════════════════════════════

void proc_hide_set(int enabled)
{
    proc_hide_enabled = enabled;
    klog("[svc]: proc_hide_enabled = %d", enabled);
}

// 系统进程豁免开关：默认启用，防止 adb install/am start 被误拦。
void sys_exempt_set(int enabled)
{
    sys_exempt_enabled = enabled ? 1 : 0;
    klog("[svc]: sys_exempt_enabled = %d (uid_max=%d)",
         sys_exempt_enabled, sys_exempt_uid_max);
}

// 调整豁免 UID 上限。合法范围 [1, 100000]；越界保持默认。
void sys_exempt_set_uid_max(int uid_max)
{
    if (uid_max <= 0 || uid_max > 100000) {
        klog("[svc]: sys_exempt uid_max out of range: %d (keep %d)",
             uid_max, sys_exempt_uid_max);
        return;
    }
    sys_exempt_uid_max = uid_max;
    klog("[svc]: sys_exempt_uid_max = %d", sys_exempt_uid_max);
}

void comm_hide_set(int enabled)
{
    comm_hide_enabled = enabled;
    klog("[svc]: comm_hide_enabled = %d", enabled);
}

int hide_pid_add(int pid)
{
    if (pid <= 0) return -1;
    if (custom_hide_pid_count >= HIDE_PID_MAX_COUNT) return -2;
    for (int i = 0; i < custom_hide_pid_count; i++)
        if (custom_hide_pid[i] == pid) return -3;
    custom_hide_pid[custom_hide_pid_count++] = pid;
    klog("hide_pid_add: %d, total: %d", pid, custom_hide_pid_count);
    return 0;
}

int hide_pid_remove(int pid)
{
    for (int i = 0; i < custom_hide_pid_count; i++) {
        if (custom_hide_pid[i] == pid) {
            if (i < custom_hide_pid_count - 1)
                custom_hide_pid[i] = custom_hide_pid[custom_hide_pid_count - 1];
            custom_hide_pid_count--;
            klog("hide_pid_remove: %d, total: %d", pid, custom_hide_pid_count);
            return 0;
        }
    }
    return -2;
}

void hide_pid_clear(void) { custom_hide_pid_count = 0; }
int  hide_pid_count(void) { return custom_hide_pid_count; }

int hide_pid_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < custom_hide_pid_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%d\n", custom_hide_pid[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

// getdents64 返回的 dirent 结构
struct lkp_linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};
#ifndef DT_DIR
#define DT_DIR 4
#endif

// 过滤 /proc 下命中隐藏 PID 的目录项。
// 非 /proc 目录几乎不会出现"目录名是一个纯数字且恰好等于某个 PID"的情况，
// 所以仅依据 d_name 纯数字 + 命中隐藏列表来过滤，误伤率极低。
void after_getdents64(hook_fargs3_t *args, void *udata)
{
    if (!proc_hide_enabled || custom_hide_pid_count == 0) return;

    long ret = (long)args->ret;
    if (ret <= 0 || ret > 1048576) return;  // 上限 1MB

    void __user *u_buf = (void __user *)(unsigned long)syscall_argn(args, 1);
    if (!u_buf) return;

    // 被隐藏进程自身访问 /proc 时不过滤
    int pid = 0, tgid = 0;
    if (current_pid_tgid(&pid, &tgid) == 0) {
        if (is_hidden_pid(pid) || is_hidden_pid(tgid)) return;
    }

    enum { CHUNK = 4096 };
    char kbuf[CHUNK];
    long processed = 0;
    long out_total = 0;

    while (processed < ret) {
        long take = ret - processed;
        if (take > CHUNK) take = CHUNK;

        if (__arch_copy_from_user(kbuf,
                (const void __user *)((char __user *)u_buf + processed), take) != 0)
            return;

        long off = 0;
        long write_off = 0;
        while (off < take) {
            struct lkp_linux_dirent64 *de = (struct lkp_linux_dirent64 *)(kbuf + off);
            unsigned short reclen = de->d_reclen;
            if (reclen == 0 || off + reclen > take) {
                // 本 chunk 末尾残缺，回退
                take = off;
                break;
            }

            int skip = 0;
            if (de->d_type == DT_DIR || de->d_type == 0) {
                int nlen = 0;
                int name_max = reclen - (int)offsetof(struct lkp_linux_dirent64, d_name);
                while (nlen < name_max && de->d_name[nlen] != '\0') nlen++;
                if (is_hidden_pid_str(de->d_name, nlen)) {
                    klog("[svc]: filter /proc dirent '%.*s'", nlen, de->d_name);
                    skip = 1;
                }
            }

            if (!skip) {
                if (write_off != off) memmove(kbuf + write_off, de, reclen);
                write_off += reclen;
            }
            off += reclen;
        }

        if (compat_copy_to_user(
                (void __user *)((char __user *)u_buf + out_total), kbuf, write_off) != 0)
            return;

        out_total += write_off;
        processed += off;
    }

    args->ret = out_total;
}