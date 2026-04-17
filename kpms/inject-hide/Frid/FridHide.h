#ifndef FRIDA_HIDE_H
#define FRIDA_HIDE_H

#include "../Struct/CStruct.h"
#include "../../kernel/include/hook.h"

struct seq_file;

void frida_hide_install(void);
void frida_hide_uninstall(void);

static int is_hiden_module(struct seq_file *m);
static void *memmem_local(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

void before_show_map_vma(hook_fargs2_t *args, void *udata);
void after_show_map_vma(hook_fargs2_t *args, void *udata);
int is_hiden_comm(const char *comm);
void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata);
u16 ntohs(u16 port);
void before_connect(hook_fargs3_t *args, void *udata);

// libdobbyproject.so 隐藏相关
void before_openat(hook_fargs4_t *args, void *udata);
void before_faccessat(hook_fargs3_t *args, void *udata);
void dobby_hide_set_file_hide(int enabled);
extern int file_hide_enabled;

// 自定义隐藏 SO 列表管理
#define HIDE_SO_MAX_COUNT 32
#define HIDE_SO_NAME_LEN  128

int hide_so_add(const char *name);
int hide_so_remove(const char *name);
void hide_so_clear(void);
int hide_so_count(void);
int hide_so_dump(char *buf, int buf_len);
int is_custom_hidden_so(const char *str);

// ─────────────────────────────────────────────────────────────
//  PID 级隐藏（针对 /proc/<pid>/mem 读取方反检测）
//  启用后：目标进程 readdir("/proc") 看不到 hide_pid 目录；
//          目标进程 open/faccessat "/proc/<hide_pid>/..." 返回 -ENOENT；
//          UID==0 或自身是 hide_pid 的调用方不受影响（保证你的
//          su + dd/cat 子进程能正常读写 /proc/<target>/mem）。
// ─────────────────────────────────────────────────────────────
#define HIDE_PID_MAX_COUNT 16

int  hide_pid_add(int pid);
int  hide_pid_remove(int pid);
void hide_pid_clear(void);
int  hide_pid_count(void);
int  hide_pid_dump(char *buf, int buf_len);
int  is_hidden_pid(int pid);

extern int proc_hide_enabled;
void proc_hide_set(int enabled);

void after_getdents64(hook_fargs3_t *args, void *udata);

// ─────────────────────────────────────────────────────────────
//  包名级隐藏（推荐：PID 会变，包名稳定）
//  - 注册一个包名 → 模块在 __get_task_comm hook 里自动把对应 tgid
//    加进 hide_pid 列表并启用 proc_hide；
//  - 匹配方式：task->comm 只有 16 字节，做前缀 memcmp(min(15, len))。
// ─────────────────────────────────────────────────────────────
#define HIDE_PKG_MAX_COUNT  16
#define HIDE_PKG_NAME_LEN   128

int  hide_pkg_add(const char *name);
int  hide_pkg_remove(const char *name);
void hide_pkg_clear(void);
int  hide_pkg_count(void);
int  hide_pkg_dump(char *buf, int buf_len);
int  is_hidden_pkg_comm(const char *comm);

// ─────────────────────────────────────────────────────────────
//  线程名 (comm) 隐藏：__get_task_comm hook 命中则将 comm 擦为空格。
//  对 ps / /proc/<pid>/comm / status Name: 等路径生效。
//  运行时可增删查；默认种子为 frida 相关线程。
// ─────────────────────────────────────────────────────────────
#define HIDE_COMM_MAX_COUNT 32
#define HIDE_COMM_NAME_LEN  32  // task->comm 实际只 16 字节，32 足够存关键词

int  hide_comm_add(const char *name);
int  hide_comm_remove(const char *name);
void hide_comm_clear(void);
int  hide_comm_count(void);
int  hide_comm_dump(char *buf, int buf_len);

extern int comm_hide_enabled;
void comm_hide_set(int enabled);

#endif //FRIDA_HIDE_H