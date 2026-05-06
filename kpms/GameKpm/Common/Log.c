#include "Log.h"

/* KPM 加载器不导出 memset / memmove / memcpy，编译器 -O2 可能合并出来 — 提供本地弱实现 */
void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

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

/* 默认关闭，避免 dmesg 噪声；通过 control0 "enable_log" 打开 */
int gk_log_enabled = 0;

void gk_log_set(int enabled)
{
    gk_log_enabled = enabled ? 1 : 0;
    glog_always("gk_log_enabled = %d", gk_log_enabled);
}
