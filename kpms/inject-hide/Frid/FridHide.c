#include "FridHide.h"
#include "../Config/Log.h"
#include <linux/string.h>

void frida_hide_install(void)
{
    klog("[SFK] frida_hide_install");
}

void frida_hide_uninstall(void)
{
    klog("[SFK] frida_hide_uninstall");
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
        NULL
    };

    for (int i = 0; keywords[i] != NULL; ++i) {
        if (memmem_local(m->buf, m->count, keywords[i], strlen(keywords[i])))
            return 1;
    }
    return 0;
}

/*
void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    if (m && m->buf) {
        // 记录 seq_file 中的count，在 after hook 中设置 count 为记录值
        args->local.data0 = m->count;
    } 
}

void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (m && m->buf) {
        if (args->local.data0 && is_hiden_module(m)) {  // is_hiden_module 查找 frida-agent 等字符串
            pr_info("inject-hide: maps hide -> frida-agent \n");
            m->count = args->local.data0;  // 恢复原来的 count 值
        }
    }
}
    */