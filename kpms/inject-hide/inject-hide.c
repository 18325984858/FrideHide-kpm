/*
 * @file   svc.c (formerly inject-hide.c)
 * @brief  KPM 入口与 control0 命令分发器。
 *
 * 三大隐藏能力：
 *   - proc_hide  : /proc/<pid> getdents64 过滤 + openat/faccessat 拦截
 *   - file_hide  : 按 custom_hide_so[] 关键字隐藏 .so 路径和 maps 条目
 *   - comm_hide  : 按 custom_hide_comm[] 关键字擦写 task->comm
 *
 * 另有多份运行时可增删的列表：hide_pid / hide_so / hide_pkg / hide_comm。
 *
 * 所有操作都通过 control0 字符串命令发起，上层由 KpCtl
 * (app/src/main/cpp/ReadProcessMemory/kp_ctl.cpp) 通过
 * SUPERCALL_KPM_CONTROL 投递到这里。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "Frid/FridHide.h"
#include "Config/Log.h"

///< The name of the module, each KPM must has a unique name.
///< 必须与用户空间 kp_ctl.cpp 里的 MODULE_NAME 保持一致。
KPM_NAME("kpm-svc");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("SFK");

///< The description.
KPM_DESCRIPTION("system service module");

/**
 * =============================================================================
 *  KPM control0 用法说明 (Usage)
 * =============================================================================
 *
 *  通过 KPM control0 接口发送命令字符串 (args) 控制模块行为:
 *
 *  1. 文件级隐藏开关:
 *     - "enable_file_hide"       启用文件级隐藏 (openat/faccessat 拦截)
 *     - "disable_file_hide"      禁用文件级隐藏
 *
 *  2. 自定义隐藏 SO 列表管理 (支持指定多个要隐藏的 SO 模块):
 *     - "add_hide_so:<name>"     添加一个要隐藏的 SO 关键词
 *       示例: "add_hide_so:libexample.so"
 *              "add_hide_so:myinject"
 *       可多次调用添加多个, 最多支持 32 个
 *
 *     - "add_hide_so:<n1>,<n2>,<n3>"  一次添加多个, 用英文逗号分隔
 *       示例: "add_hide_so:libfoo.so,libbar.so,libbaz.so"
 *
 *     - "remove_hide_so:<name>"  移除一个已添加的隐藏关键词
 *       示例: "remove_hide_so:libexample.so"
 *
 *     - "list_hide_so"           列出当前所有自定义隐藏的 SO 关键词
 *
 *     - "clear_hide_so"          清空所有自定义隐藏的 SO 关键词
 *
 *  3. 其它字符串: echo 回显
 *
 *  用法示例 (shell):
 *    # 添加自定义隐藏 SO
 *    kpatch ctl kpm-svc "add_hide_so:libexample.so"
 *    kpatch ctl kpm-svc "add_hide_so:libfoo.so,libbar.so"
 *
 *    # 查看当前隐藏列表
 *    kpatch ctl kpm-svc "list_hide_so"
 *
 *    # 移除指定 SO
 *    kpatch ctl kpm-svc "remove_hide_so:libexample.so"
 *
 *    # 清空全部自定义隐藏
 *    kpatch ctl kpm-svc "clear_hide_so"
 *
 *    # 启用文件级隐藏
 *    kpatch ctl kpm-svc "enable_file_hide"
 *
 * =============================================================================
 */

/*

通过 APatch UI 使用
点击模块卡片上的 「参数」 按钮，在弹出的输入框中填写以下命令字符串：

输入内容	功能
add_hide_so:libexample.so	添加一个要隐藏的 SO
add_hide_so:libfoo.so,libbar.so	一次添加多个（逗号分隔）
list_hide_so	查看当前隐藏列表
remove_hide_so:libexample.so	移除指定 SO
clear_hide_so	清空全部自定义隐藏
enable_file_hide	启用文件级隐藏（openat/faccessat）
disable_file_hide	禁用文件级隐藏
每次点「参数」只能发送一条命令，模块会返回执行结果显示在界面上。

*/


/**
 * @brief initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long svc_init(const char *args, const char *event, void *__user reserved)
{
    klog("[svc] init, event: %s, args: %s", event, args);
    klog("kernelpatch version: %x", kpver);

    frida_hide_install();

    klog("[svc] install");
    return 0;
}

static long svc_control0(const char *args, char *__user out_msg, int outlen)
{
    klog("[svc] control0, args: %s", args);

    if (args) {
        // 文件级隐藏开关
        if (strncmp(args, "enable_file_hide", 16) == 0) {
            dobby_hide_set_file_hide(1);
            char msg[] = "file_hide enabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        } else if (strncmp(args, "disable_file_hide", 17) == 0) {
            dobby_hide_set_file_hide(0);
            char msg[] = "file_hide disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }

        // 添加自定义隐藏 SO (支持逗号分隔多个)
        if (strncmp(args, "add_hide_so:", 12) == 0) {
            const char *names = args + 12;
            char buf[HIDE_SO_NAME_LEN];
            char result[256] = "";
            int added = 0, failed = 0;

            while (*names) {
                const char *comma = names;
                while (*comma && *comma != ',') comma++;
                int len = comma - names;
                if (len > 0 && len < HIDE_SO_NAME_LEN) {
                    memcpy(buf, names, len);
                    buf[len] = '\0';
                    if (hide_so_add(buf) == 0) {
                        added++;
                    } else {
                        failed++;
                    }
                }
                names = *comma ? comma + 1 : comma;
            }

            snprintf(result, sizeof(result), "added: %d, failed: %d, total: %d", added, failed, hide_so_count());
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }

        // 移除自定义隐藏 SO
        if (strncmp(args, "remove_hide_so:", 15) == 0) {
            const char *name = args + 15;
            int ret = hide_so_remove(name);
            char result[128];
            if (ret == 0) {
                snprintf(result, sizeof(result), "removed '%s', total: %d", name, hide_so_count());
            } else {
                snprintf(result, sizeof(result), "remove failed: '%s' not found", name);
            }
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }

        // 列出所有自定义隐藏 SO
        if (strncmp(args, "list_hide_so", 12) == 0) {
            char list_buf[1024];
            int count = hide_so_count();
            int offset = snprintf(list_buf, sizeof(list_buf), "total: %d\n", count);
            if (count > 0) {
                hide_so_dump(list_buf + offset, sizeof(list_buf) - offset);
            }
            compat_copy_to_user(out_msg, list_buf, strlen(list_buf) + 1);
            return 0;
        }

        // 清空所有自定义隐藏 SO
        if (strncmp(args, "clear_hide_so", 13) == 0) {
            hide_so_clear();
            char msg[] = "all custom hide_so cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }

        // ───── 包名级隐藏列表 (hide_pkg) ─────
        // add_hide_pkg:<name>[,<name>...]
        if (strncmp(args, "add_hide_pkg:", 13) == 0) {
            const char *names = args + 13;
            char buf[HIDE_PKG_NAME_LEN];
            char result[256] = "";
            int added = 0, failed = 0;
            while (*names) {
                const char *comma = names;
                while (*comma && *comma != ',') comma++;
                int len = comma - names;
                if (len > 0 && len < HIDE_PKG_NAME_LEN) {
                    memcpy(buf, names, len);
                    buf[len] = '\0';
                    if (hide_pkg_add(buf) == 0) added++; else failed++;
                }
                names = *comma ? comma + 1 : comma;
            }
            snprintf(result, sizeof(result), "added: %d, failed: %d, total: %d",
                     added, failed, hide_pkg_count());
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "remove_hide_pkg:", 16) == 0) {
            const char *name = args + 16;
            int ret = hide_pkg_remove(name);
            char result[160];
            if (ret == 0)
                snprintf(result, sizeof(result), "removed '%s', total: %d", name, hide_pkg_count());
            else
                snprintf(result, sizeof(result), "remove failed: '%s' not found", name);
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "list_hide_pkg", 13) == 0) {
            char list_buf[1024];
            int count = hide_pkg_count();
            int offset = snprintf(list_buf, sizeof(list_buf), "total: %d\n", count);
            if (count > 0) hide_pkg_dump(list_buf + offset, sizeof(list_buf) - offset);
            compat_copy_to_user(out_msg, list_buf, strlen(list_buf) + 1);
            return 0;
        }
        if (strncmp(args, "clear_hide_pkg", 14) == 0) {
            hide_pkg_clear();
            char msg[] = "all hide_pkg cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }

        // ───── 线程名 (comm) 隐藏列表 (hide_comm) ─────
        // add_hide_comm:<name>[,<name>...]
        if (strncmp(args, "add_hide_comm:", 14) == 0) {
            const char *names = args + 14;
            char buf[HIDE_COMM_NAME_LEN];
            char result[256] = "";
            int added = 0, failed = 0;
            while (*names) {
                const char *comma = names;
                while (*comma && *comma != ',') comma++;
                int len = comma - names;
                if (len > 0 && len < HIDE_COMM_NAME_LEN) {
                    memcpy(buf, names, len);
                    buf[len] = '\0';
                    if (hide_comm_add(buf) == 0) added++; else failed++;
                }
                names = *comma ? comma + 1 : comma;
            }
            snprintf(result, sizeof(result), "added: %d, failed: %d, total: %d",
                     added, failed, hide_comm_count());
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "remove_hide_comm:", 17) == 0) {
            const char *name = args + 17;
            int ret = hide_comm_remove(name);
            char result[160];
            if (ret == 0)
                snprintf(result, sizeof(result), "removed '%s', total: %d", name, hide_comm_count());
            else
                snprintf(result, sizeof(result), "remove failed: '%s' not found", name);
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "list_hide_comm", 14) == 0) {
            char list_buf[1024];
            int count = hide_comm_count();
            int offset = snprintf(list_buf, sizeof(list_buf), "total: %d\n", count);
            if (count > 0) hide_comm_dump(list_buf + offset, sizeof(list_buf) - offset);
            compat_copy_to_user(out_msg, list_buf, strlen(list_buf) + 1);
            return 0;
        }
        if (strncmp(args, "clear_hide_comm", 15) == 0) {
            hide_comm_clear();
            char msg[] = "all hide_comm cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "enable_comm_hide", 16) == 0) {
            comm_hide_set(1);
            char msg[] = "comm_hide enabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "disable_comm_hide", 17) == 0) {
            comm_hide_set(0);
            char msg[] = "comm_hide disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }

        // ───── PID 级隐藏（针对 /proc/<pid>/mem 读取方反检测）─────
        if (strncmp(args, "enable_proc_hide", 16) == 0) {
            proc_hide_set(1);
            char msg[] = "proc_hide enabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "disable_proc_hide", 17) == 0) {
            proc_hide_set(0);
            char msg[] = "proc_hide disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "add_hide_pid:", 13) == 0) {
            const char *p = args + 13;
            int added = 0, failed = 0;
            while (*p) {
                int v = 0, has = 0;
                while (*p == ' ' || *p == ',') p++;
                while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; has = 1; }
                if (has) { if (hide_pid_add(v) == 0) added++; else failed++; }
                if (*p && *p != ',' && *p != ' ') break;
            }
            char result[128];
            snprintf(result, sizeof(result), "added: %d, failed: %d, total: %d",
                     added, failed, hide_pid_count());
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "remove_hide_pid:", 16) == 0) {
            const char *p = args + 16;
            int v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            char result[96];
            if (v > 0 && hide_pid_remove(v) == 0)
                snprintf(result, sizeof(result), "removed pid %d, total: %d", v, hide_pid_count());
            else
                snprintf(result, sizeof(result), "remove failed: pid %d not found", v);
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "list_hide_pid", 13) == 0) {
            char list_buf[256];
            int count = hide_pid_count();
            int offset = snprintf(list_buf, sizeof(list_buf), "total: %d\n", count);
            if (count > 0) hide_pid_dump(list_buf + offset, sizeof(list_buf) - offset);
            compat_copy_to_user(out_msg, list_buf, strlen(list_buf) + 1);
            return 0;
        }
        if (strncmp(args, "clear_hide_pid", 14) == 0) {
            hide_pid_clear();
            char msg[] = "all hide_pid cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }

        // ───── 状态查询 ─────
        // 返回当前模块各功能开关与列表统计，供前端 UI 刷新显示。
        // 输出格式 (固定字段, 便于解析):
        //   proc_hide=<0/1>
        //   file_hide=<0/1>
        //   hide_pid_count=<N>
        //   hide_so_count=<N>
        if (strncmp(args, "status", 6) == 0) {
            char status[192];
            snprintf(status, sizeof(status),
                     "proc_hide=%d\nfile_hide=%d\ncomm_hide=%d\nhide_pid_count=%d\nhide_so_count=%d\nhide_pkg_count=%d\nhide_comm_count=%d\n",
                     proc_hide_enabled, file_hide_enabled, comm_hide_enabled,
                     hide_pid_count(), hide_so_count(), hide_pkg_count(), hide_comm_count());
            compat_copy_to_user(out_msg, status, strlen(status) + 1);
            return 0;
        }
    }

    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long svc_control1(void *a1, void *a2, void *a3)
{
    klog("[svc] control1, a1: %llx, a2: %llx, a3: %llx", a1, a2, a3);
    return 0;
}

static long svc_exit(void *__user reserved)
{   
    frida_hide_uninstall();
    klog("[svc] exit");
    return 0;
}

KPM_INIT(svc_init); // 装载回调
KPM_CTL0(svc_control0); // 控制0回调
KPM_CTL1(svc_control1); // 控制1回调
KPM_EXIT(svc_exit); // 卸载回调