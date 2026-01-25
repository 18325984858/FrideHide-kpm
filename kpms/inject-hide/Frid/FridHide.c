#include "FridHide.h"
#include "../Config/Log.h"
#include <linux/string.h>

void *show_map_vma = 0;

void frida_hide_install(void)
{
    klog("frida_hide_install");


    show_map_vma = (void *) kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {

        klog("show_map_vma address: %llx", show_map_vma);

        int err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
    }

}

void frida_hide_uninstall(void)
{
    klog("frida_hide_uninstall");
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


void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;

    // 严谨检查：不仅看 m，还要看 m->buf 是否真的有地址
    if (m && (unsigned long)m->buf > 0xffffff0000000000) { 
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
             klog("inject-hide: matched and hiding!");
             m->count = (size_t)args->local.data0;
        }
    }
}