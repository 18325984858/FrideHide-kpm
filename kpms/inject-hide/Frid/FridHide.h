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

#endif //FRIDA_HIDE_H