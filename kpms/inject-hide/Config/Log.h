#ifndef LOG_H
#define LOG_H

#include <linux/printk.h>

// ═══════════════════════════════════════════════════════════════
//  统一日志宏 (Unified KPM Log Macros)
// ───────────────────────────────────────────────────────────────
//  所有普通 klog() 调用均受总开关 kpm_log_enabled 控制，可在运行
//  时通过 control0 命令 enable_log / disable_log 切换，或由 App
//  端的 InjectHideActivity 中的按钮触发。
//
//  错误级别 (klog_err) 与关键路径级别 (klog_always) 不受开关影
//  响，任何时候都会打印，便于故障排查。
// ═══════════════════════════════════════════════════════════════

// 模块日志前缀
#define LOG_TAG "[SFK] "

// 日志总开关 (默认开启)：运行时可切换
//   1 = 普通 klog/klog_dbg 打印
//   0 = 仅保留 klog_err / klog_always
extern int kpm_log_enabled;

// 设置开关的便捷 setter (Log.c 实现)
void kpm_log_set(int enabled);

// 受开关控制的常规日志（绝大多数信息都应使用这个）
#define klog(fmt, ...) \
    do { if (kpm_log_enabled) pr_info(LOG_TAG fmt "\n", ##__VA_ARGS__); } while (0)

// 调试级别，等价于 klog，语义上表示可丢弃的细节日志
#define klog_dbg(fmt, ...) \
    do { if (kpm_log_enabled) pr_info(LOG_TAG "DBG: " fmt "\n", ##__VA_ARGS__); } while (0)

// 错误级别：任何时候都打印，不受开关影响
#define klog_err(fmt, ...) pr_err(LOG_TAG "ERROR: " fmt "\n", ##__VA_ARGS__)

// 强制输出（关键生命周期/告警），不受开关影响
#define klog_always(fmt, ...) pr_info(LOG_TAG fmt "\n", ##__VA_ARGS__)


#endif //LOG_H