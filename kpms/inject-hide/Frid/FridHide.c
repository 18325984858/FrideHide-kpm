#include "FridHide.h"
#include "../Config/Log.h"
#include "linux/pid.h"
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>  // struct task_struct 的完整定义在这里
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
void *show_smap_vma = 0;
int file_hide_enabled = 0;

// 自定义隐藏 SO 列表
static char custom_hide_so[HIDE_SO_MAX_COUNT][HIDE_SO_NAME_LEN];
static int custom_hide_so_count = 0;

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

    file_hide_enabled = 0;

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

// 检查 seq_file 缓冲区中是否包含敏感关键词
static int is_hiden_module(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) return false;
    // 需要隐藏的关键词列表
    static const char *keywords[] = {
        "frida-agent",
        "frida",
        "gum-js-loop",
        "GumJS",
        "gmain",
        "libdobbyproject",
        "libdobby",
        "dobby",
        NULL
    };
    //klog("is_hiden_module buf=%p, count=%zu", m->buf, m->count);
    for (int i = 0; keywords[i] != NULL; ++i) {
        if (memmem_local(m->buf, m->count, keywords[i], strlen(keywords[i])))
            return 1;
    }
    // 检查自定义隐藏 SO 列表
    for (int i = 0; i < custom_hide_so_count; i++) {
        if (memmem_local(m->buf, m->count, custom_hide_so[i], strlen(custom_hide_so[i])))
            return 1;
    }
    return 0;
}

int is_hiden_comm(const char *comm)
{
    // 需要隐藏的线程名关键词列表
    static const char *keywords[] = {
        "gmain",
        "gum-js-loop",
        "gdbus",
        "pool-frida",
        "linjector",
    };

    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strstr(comm, keywords[i])) {
            return 1;
        }
    }
    return 0;
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
    if (comm && comm_buf_len) {
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

// 检查文件路径是否包含需要隐藏的 SO 关键词
static int is_hidden_path(const char *path)
{
    if (!path) return 0;

    static const char *keywords[] = {
        "libdobbyproject",
        "libdobby",
        "dobby",
        NULL
    };

    for (int i = 0; keywords[i] != NULL; i++) {
        if (strstr(path, keywords[i])) {
            return 1;
        }
    }
    // 检查自定义隐藏 SO 列表
    if (is_custom_hidden_so(path)) return 1;
    return 0;
}

// openat(int dirfd, const char __user *pathname, int flags, mode_t mode) hook
// 拦截打开 dobby SO 文件的操作, 需要通过 control0 "enable_file_hide" 启用
void before_openat(hook_fargs4_t *args, void *udata)
{
    if (!file_hide_enabled) return;

    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    if (!pathname) return;

    char kpath[256];
    long len = compat_strncpy_from_user(kpath, pathname, sizeof(kpath) - 1);
    if (len <= 0) return;
    kpath[len] = '\0';

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
    if (!file_hide_enabled) return;

    const char __user *pathname = (const char __user *)(unsigned long)syscall_argn(args, 1);
    if (!pathname) return;

    char kpath[256];
    long len = compat_strncpy_from_user(kpath, pathname, sizeof(kpath) - 1);
    if (len <= 0) return;
    kpath[len] = '\0';

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