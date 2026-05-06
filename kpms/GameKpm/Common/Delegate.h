#ifndef GAMEKPM_DELEGATE_H
#define GAMEKPM_DELEGATE_H

/*
 * GameKpm → kpm-svc (inject-hide) IPC 桥
 *
 * KernelPatch 提供：
 *   long module_control0(const char *name, const char *ctl_args,
 *                        char __user *out_msg, int outlen);
 * 我们用 kallsyms_lookup_name 取地址；之后 GameKpm 想触发任何
 * inject-hide 已实现的隐藏功能，统一走 delegate_svc()。
 *
 * 返回值：
 *   0  调用成功
 *   <0 调用失败（kpm-svc 未加载、符号没找到等）— GameKpm 不退出，仅打日志
 */

int  delegate_init(void);          /* init 时调一次，解析 module_control0 */
long delegate_svc(const char *cmd); /* 透传命令到 kpm-svc */

/* 一键预设：把当前目标包名/常见 frida 隐藏关键词推给 kpm-svc */
void delegate_preset_dfm(void);
void delegate_preset_pubgmhd(void);

#endif /* GAMEKPM_DELEGATE_H */
