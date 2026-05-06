/*
 * 反环境指纹：uname 改写
 *
 * 检测点 (anticheat-arch.md §3.5)：游戏读 uname.release 看是否含
 * "KernelPatch" / "dirty" / "+" 等被改造内核的特征。
 */
#include "AntiEnv.h"
#include "../Common/Log.h"
#include "../Common/Target.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <ksyms.h>
#include <uapi/asm-generic/unistd.h>

#define UTS_LEN     65
#define UTS_RELEASE 130
#define UTS_VERSION 195

int g_uname_spoof_enabled = 0;
static int hooked = 0;

static unsigned long (*_arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

void anti_env_set_uname(int enabled)
{
    g_uname_spoof_enabled = enabled ? 1 : 0;
    glog("uname_spoof=%d", g_uname_spoof_enabled);
}

/* 在 buf 中查找 needle（不区分大小写），命中则全部覆盖为 fill */
static int redact(char *buf, int len, const char *needle, char fill)
{
    int nlen = strlen(needle);
    if (nlen == 0 || nlen > len) return 0;
    int hit = 0;
    for (int i = 0; i + nlen <= len; i++) {
        int eq = 1;
        for (int j = 0; j < nlen; j++) {
            char a = buf[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { eq = 0; break; }
        }
        if (eq) {
            for (int j = 0; j < nlen; j++) buf[i + j] = fill;
            hit = 1;
            i += nlen - 1;
        }
    }
    return hit;
}

static void redact_field(void __user *base, int field_off)
{
    char field[UTS_LEN + 1];
    if (_arch_copy_from_user(field, (char __user *)base + field_off, UTS_LEN) != 0) return;
    field[UTS_LEN] = '\0';
    int n = strlen(field);
    int touched = 0;
    touched |= redact(field, n, "kernelpatch", 'X');
    touched |= redact(field, n, "kpatch",      'X');
    touched |= redact(field, n, "apatch",      'X');
    touched |= redact(field, n, "dirty",       'X');
    if (touched) {
        (void)compat_copy_to_user((char __user *)base + field_off, field, UTS_LEN);
        glog_dbg("uname[%d] redacted -> '%s'", field_off, field);
    }
}

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (!g_uname_spoof_enabled) return;
    if ((long)args->ret != 0)   return;
    if (!is_target_current())   return;
    if (!_arch_copy_from_user)  return;

    void __user *uts = (void __user *)syscall_argn(args, 0);
    if (!uts) return;

    redact_field(uts, UTS_RELEASE);
    redact_field(uts, UTS_VERSION);
}

int anti_env_install(void)
{
    _arch_copy_from_user = (typeof(_arch_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!_arch_copy_from_user) {
        glog_err("__arch_copy_from_user not found — uname spoof disabled");
        return -1;
    }
    hook_err_t err = fp_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    if (err) { glog_err("hook __NR_uname failed: %d", err); return -2; }
    hooked = 1;
    glog("hook __NR_uname ok");
    return 0;
}

void anti_env_uninstall(void)
{
    if (hooked) { fp_unhook_syscalln(__NR_uname, 0, after_uname); hooked = 0; }
}
