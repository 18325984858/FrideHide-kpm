#include "Log.h"

// KernelPatch 没有把 memset 导出给 KPM，编译器会为结构体清零自动插入 memset，
// 所以在 KPM 内部提供一份弱实现，避免 "unknown symbol: memset" 加载失败。
void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

// 同理：数组元素挪位 (a[j-1]=a[j] 循环) 高优化等级会被合并为 memmove 调用，
// KernelPatch 也未导出 memmove 给 KPM，提供一份处理重叠的本地实现。
void *memmove(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

// 默认关闭：减少 dmesg 噪声与日志侧信道泄露；如需排错可在 App 按钮开启。
int kpm_log_enabled = 0;

void kpm_log_set(int enabled)
{
    kpm_log_enabled = enabled ? 1 : 0;
    // 使用 klog_always 保证这条信息永远能看到，便于确认开关状态
    klog_always("kpm_log_enabled = %d", kpm_log_enabled);
}
