/*
 * @file   Frid/FridHide.c
 * @brief  inject-hide 的核心 hook 与隐藏列表实现。
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

void *show_map_vma = 0;
char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = 0;  // 为了后续能够调用，定义成函数指针变量
unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

int __get_task_comm_hook_status = 0;
int connect_hook_status = 0;
int openat_hook_status = 0;
int faccessat_hook_status = 0;
int getdents64_hook_status = 0;
void *show_smap_vma = 0;
int file_hide_enabled = 0;
int proc_hide_enabled = 0;
int comm_hide_enabled = 1;  // 线程名隐藏总开关，默认开启

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

void frida_hide_install(void)
{
    klog("frida_hide_install");

    // 默认监控的包名（可随后通过 control0: add_hide_pkg / remove_hide_pkg 调整）
    hide_pkg_add("com.example.dobbyproject");

    // 默认隐藏的 SO 关键词（可随后通过 control0: add_hide_so / remove_hide_so 调整）
    hide_so_add("libdobbyproject");
    hide_so_add("libdobby");
    hide_so_add("dobby");
    hide_so_add("frida-agent");
    hide_so_add("frida");
    hide_so_add("gum-js-loop");
    hide_so_add("GumJS");
    hide_so_add("gmain");

    // 默认隐藏的线程名 (comm) 关键词（可随后通过 control0 调整）
    hide_comm_add("gmain");
    hide_comm_add("gum-js-loop");
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
        hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, NULL);
        openat_hook_status = err ? 0 : 1;
        klog("openat hook: %s", openat_hook_status ? "success" : "failed");
    }

    // Hook faccessat to prevent file existence check
    {
        hook_err_t err = fp_hook_syscalln(__NR_faccessat, 3, before_faccessat, 0, NULL);
        faccessat_hook_status = err ? 0 : 1;
        klog("faccessat hook: %s", faccessat_hook_status ? "success" : "failed");
    }

    // Hook getdents64 to filter /proc dirents for hidden PIDs (PID 级隐藏)
    {
        hook_err_t err = fp_hook_syscalln(__NR_getdents64, 3, 0, after_getdents64, NULL);
        getdents64_hook_status = err ? 0 : 1;
        klog("getdents64 hook: %s", getdents64_hook_status ? "success" : "failed");
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
        fp_unhook_syscalln(__NR_openat, before_openat, 0);
        openat_hook_status = 0;
    }

    if(faccessat_hook_status) {
        fp_unhook_syscalln(__NR_faccessat, before_faccessat, 0);
        faccessat_hook_status = 0;
    }

    if(getdents64_hook_status) {
        fp_unhook_syscalln(__NR_getdents64, 0, after_getdents64);
        getdents64_hook_status = 0;
    }

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
             klog("inject-hide: matched and hiding! ");
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
                    klog("inject-hide: auto-hide pkg '%s' tgid=%d", comm, tgid);
                }
            }
        }
        if (is_hiden_comm(comm)){
            pr_info("inject-hide: get_task_comm hide -> %s\n", comm);
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

        pr_warn("inject-hide: connect to frida-agent, comm: %s, port: %d\n", comm, port);
        if (!strstr(comm, "adbd")) {  // 只允许 adbd 连接 frida
            pr_warn("inject-hide: connect to frida-agent blocked, comm: %s, port: %d\n", comm, port);
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

// 路径是否形如 /proc/<hidden_pid>[/...]
static int is_hidden_proc_path(const char *path)
{
    if (!path) return 0;
    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' ||
        path[3] != 'o' || path[4] != 'c' || path[5] != '/') return 0;
    const char *p = path + 6;
    const char *start = p;
    while (*p >= '0' && *p <= '9') p++;
    if (p == start) return 0;
    if (*p != '\0' && *p != '/') return 0;
    return is_hidden_pid_str(start, (int)(p - start));
}

// 获取调用方 UID / PID，失败返回 -1
static int current_uid_safe(void)
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

// 判断是否为"可信调用方"：UID==0（su + dd/cat/base64 等 root 子进程）
// 或 PID/TGID 在隐藏列表中（reader app 自身）。
// 命中则 hook 放行，保证 mem_reader 端工作不受影响。
static int is_trusted_caller(void)
{
    if (current_uid_safe() == 0) return 1;
    int pid = 0, tgid = 0;
    if (current_pid_tgid(&pid, &tgid) == 0) {
        if (is_hidden_pid(pid) || is_hidden_pid(tgid)) return 1;
    }
    return 0;
}

// openat(int dirfd, const char __user *pathname, int flags, mode_t mode) hook
// 拦截打开 dobby SO 文件的操作, 需要通过 control0 "enable_file_hide" 启用
void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    if (!pathname) return;

    char kpath[256];
    long len = compat_strncpy_from_user(kpath, pathname, sizeof(kpath) - 1);
    if (len <= 0) return;
    kpath[len] = '\0';

    // PID 级隐藏：拦截对 /proc/<hidden_pid>/... 的访问
    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller()) {
        klog("inject-hide: blocking openat(proc) -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
        return;
    }

    if (!file_hide_enabled) return;

    if (is_hidden_path(kpath)) {
        klog("inject-hide: blocking openat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// faccessat(int dirfd, const char __user *pathname, int mode) hook
// 拦截对 dobby SO 文件的存在性检查
void before_faccessat(hook_fargs3_t *args, void *udata)
{
    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    if (!pathname) return;

    char kpath[256];
    long len = compat_strncpy_from_user(kpath, pathname, sizeof(kpath) - 1);
    if (len <= 0) return;
    kpath[len] = '\0';

    // PID 级隐藏
    if (proc_hide_enabled && is_hidden_proc_path(kpath) && !is_trusted_caller()) {
        klog("inject-hide: blocking faccessat(proc) -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
        return;
    }

    if (!file_hide_enabled) return;

    if (is_hidden_path(kpath)) {
        klog("inject-hide: blocking faccessat -> %s", kpath);
        args->skip_origin = 1;
        args->ret = -ENOENT;
    }
}

// 供外部调用: 启用/禁用文件级隐藏
void dobby_hide_set_file_hide(int enabled)
{
    file_hide_enabled = enabled;
    klog("inject-hide: file_hide_enabled = %d", enabled);
}

// ═══════════════════════════════════════════════════════════════
//  PID 级隐藏：getdents64 过滤 + PID 列表管理
// ═══════════════════════════════════════════════════════════════

void proc_hide_set(int enabled)
{
    proc_hide_enabled = enabled;
    klog("inject-hide: proc_hide_enabled = %d", enabled);
}

void comm_hide_set(int enabled)
{
    comm_hide_enabled = enabled;
    klog("inject-hide: comm_hide_enabled = %d", enabled);
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
                    klog("inject-hide: filter /proc dirent '%.*s'", nlen, de->d_name);
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