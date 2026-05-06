#include "Delegate.h"
#include "Log.h"

#include <linux/string.h>
#include <ksyms.h>

/* 与 kernel/patch/include/module.h 对齐的签名 */
typedef long (*module_control0_fn)(const char *name, const char *ctl_args,
                                   char __user *out_msg, int outlen);

static module_control0_fn _mc0 = 0;

/* 目标 KPM 名称：必须与 inject-hide 的 KPM_NAME 一致 */
#define SVC_NAME "kpm-svc"

int delegate_init(void)
{
    _mc0 = (module_control0_fn)kallsyms_lookup_name("module_control0");
    if (!_mc0) {
        /* KernelPatch 默认未把 module_control0 加入 KP_EXPORT_SYMBOL —
         * 桥接退化为 no-op；用户态 game_reload.sh 会直接通过
         * `kpatch kpm ctl0 kpm-svc <cmd>` 串行触发 inject-hide 的隐藏链。 */
        glog_always("module_control0 not exported — delegate disabled (use shell orchestration instead)");
        return -1;
    }
    glog("module_control0 = %llx", (unsigned long long)_mc0);
    return 0;
}

/*
 * 把命令传给 kpm-svc。
 *
 * out_msg 传 NULL / outlen=0 是允许的：kpm-svc 的 ctl_copy_out 已对
 *   (out_msg==NULL || outlen<=0) 静默返回。
 *
 * 当 KernelPatch 没有导出 module_control0 时（默认情况），桥不可用，
 * 静默返回 -1 — 用户态 game_reload.sh 会兜底。
 */
long delegate_svc(const char *cmd)
{
    if (!_mc0)            return -1;          /* 桥未就绪：静默 */
    if (!cmd || !*cmd)    return -2;

    long rc = _mc0(SVC_NAME, cmd, 0, 0);
    glog("delegate_svc('%s') rc=%ld", cmd, rc);
    return rc;
}

/* 桥可用时才发命令；不可用就什么也不做 */
static void preset_send(const char *cmd)
{
    if (_mc0) (void)delegate_svc(cmd);
}

void delegate_preset_dfm(void)
{
    /* 把游戏 tgid + UID 自动加入 kpm-svc 的 trusted 列表（add_hide_pkg 内部已处理） */
    preset_send("add_hide_pkg:com.tencent.tmgp.dfm");

    /* frida / gum / dobby 相关的线程名 */
    preset_send("add_hide_comm:gum-js-loop");
    preset_send("add_hide_comm:gmain");
    preset_send("add_hide_comm:gdbus");
    preset_send("add_hide_comm:linjector");
    preset_send("add_hide_comm:pool-frida");
    preset_send("add_hide_comm:GumJS");

    /* SO 关键词（路径子串匹配） */
    preset_send("add_hide_so:frida");
    preset_send("add_hide_so:gum");
    preset_send("add_hide_so:libdobbyproject");
    preset_send("add_hide_so:libdobby");

    /* 启用文件级隐藏 */
    preset_send("enable_file_hide");
}

void delegate_preset_pubgmhd(void)
{
    preset_send("add_hide_pkg:com.tencent.tmgp.pubgmhd");
    preset_send("add_hide_comm:gum-js-loop");
    preset_send("add_hide_comm:gmain");
    preset_send("add_hide_comm:linjector");
    preset_send("add_hide_so:frida");
    preset_send("add_hide_so:gum");
    preset_send("enable_file_hide");
}
