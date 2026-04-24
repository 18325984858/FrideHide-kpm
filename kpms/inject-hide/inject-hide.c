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
#include "Root/RootHide.h"
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
    root_hide_install();   // 仅播种默认 root 关键词，需 control0 "enable_root_hide" 启用

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
            static char list_buf[8192];
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

            /* ── 自动豁免：把调用方（即 game 自身）瞬间标记为可信 ──
             *   1) 调用方 tgid 加入 hide_pid → is_trusted_caller() 命中
             *      is_hidden_pid(tgid) → game 全部线程立即 trusted
             *   2) 调用方 UID 加入 root_exempt_uid → 未来 fork 出来的
             *      子进程（双 fork daemon、popen sh 等）也走 UID 豁免
             *  注意：无论 add 是否成功（包名可能早已被 install 默认列入，
             *  导致 added=0/failed=1），只要被调用过这个命令，调用方就
             *  应该被信任，否则会出现 "包名 install 时已加 → 用户层
             *  add 永远 failed → 自动豁免永不触发 → game 自杀" 的死锁。 */
            {
                int pid = 0, tgid = 0;
                if (current_pid_tgid_safe(&pid, &tgid) == 0 && tgid > 0) {
                    hide_pid_add(tgid);
                }
                int uid = current_uid_safe();
                if (uid > 0) {
                    root_exempt_uid_add(uid);
                }
            }

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
            static char list_buf[8192];
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
            static char list_buf[8192];
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
            static char list_buf[2048];
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
        // 注意：status_root 必须放在 status 之前，否则会被前缀匹配吞掉
        if (strncmp(args, "status_root", 11) == 0) {
            char status[200];
            snprintf(status, sizeof(status),
                     "root_hide=%d\nfile_hide=%d\nroot_file_hide=%d\nroot_kw_count=%d\nexempt_uid_count=%d\n",
                     root_hide_enabled, file_hide_enabled,
                     root_file_hide_enabled, root_kw_count(),
                     root_exempt_uid_count());
            compat_copy_to_user(out_msg, status, strlen(status) + 1);
            return 0;
        }
        if (strncmp(args, "status", 6) == 0) {
            /* 自动豁免：UI 进入 InjectHideActivity 必发 status；这是
             * 整个 refreshAll 流程时序最早的命令。在这里把调用方 tgid
             * 加入 hide_pid、UID 加入 root_exempt_uid，可以保证后续
             * list_hide_so / list_hide_pkg / list_running_apps 等调用
             * 都已 trusted，避免它们被 P0 stat/openat hook 干扰。 */
            {
                int pid = 0, tgid = 0;
                if (current_pid_tgid_safe(&pid, &tgid) == 0 && tgid > 0)
                    hide_pid_add(tgid);
                int uid = current_uid_safe();
                if (uid > 0) root_exempt_uid_add(uid);
            }
            char status[256];
            snprintf(status, sizeof(status),
                     "proc_hide=%d\nfile_hide=%d\ncomm_hide=%d\nhide_pid_count=%d\nhide_so_count=%d\nhide_pkg_count=%d\nhide_comm_count=%d\nsys_exempt=%d\nsys_exempt_uid_max=%d\nlog_enabled=%d\n",
                     proc_hide_enabled, file_hide_enabled, comm_hide_enabled,
                     hide_pid_count(), hide_so_count(), hide_pkg_count(), hide_comm_count(),
                     sys_exempt_enabled, sys_exempt_uid_max, kpm_log_enabled);
            compat_copy_to_user(out_msg, status, strlen(status) + 1);
            return 0;
        }

        // ═══════════════════════════════════════════════════════════════
        //  日志总开关（影响所有 klog/klog_dbg，但不影响 klog_err/always）
        //  - enable_log / disable_log
        //  - status_log : 仅返回当前日志开关状态
        // ═══════════════════════════════════════════════════════════════
        if (strncmp(args, "enable_log", 10) == 0) {
            kpm_log_set(1);
            char msg[] = "kpm_log enabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "disable_log", 11) == 0) {
            kpm_log_set(0);
            char msg[] = "kpm_log disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "status_log", 10) == 0) {
            char msg[48];
            snprintf(msg, sizeof(msg), "log_enabled=%d\n", kpm_log_enabled);
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }

        // ═══════════════════════════════════════════════════════════════
        //  系统进程豁免（sys_exempt）
        //  默认启用；UID < sys_exempt_uid_max 的调用方被视为 trusted，
        //  避免 installd/system_server/surfaceflinger 等被误拦。
        //  - enable_sys_exempt / disable_sys_exempt
        //  - set_sys_exempt_uid:<N>    设置 UID 阈值 (默认 10000)
        // ═══════════════════════════════════════════════════════════════
        if (strncmp(args, "enable_sys_exempt", 17) == 0) {
            sys_exempt_set(1);
            char msg[] = "sys_exempt enabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "disable_sys_exempt", 18) == 0) {
            sys_exempt_set(0);
            char msg[] = "sys_exempt disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "set_sys_exempt_uid:", 19) == 0) {
            const char *p = args + 19;
            int v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            sys_exempt_set_uid_max(v);
            char msg[64];
            snprintf(msg, sizeof(msg), "sys_exempt_uid_max=%d", sys_exempt_uid_max);
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }

        // ═══════════════════════════════════════════════════════════════
        //  Root 痕迹隐藏（独立模块 Root/RootHide.c）
        //  - enable_root_hide / disable_root_hide
        //  - add_hide_root:<kw>[,<kw>...]
        //  - remove_hide_root:<kw>
        //  - list_hide_root / clear_hide_root / reset_hide_root
        //  - status_root
        // ═══════════════════════════════════════════════════════════════
        if (strncmp(args, "enable_root_hide", 16) == 0) {
            root_hide_set(1);
            char msg[64];
            snprintf(msg, sizeof(msg), "root_hide enabled, kw=%d", root_kw_count());
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }
        if (strncmp(args, "disable_root_hide", 17) == 0) {
            root_hide_set(0);
            char msg[] = "root_hide disabled";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "add_hide_root:", 14) == 0) {
            const char *names = args + 14;
            char buf[ROOT_KW_NAME_LEN];
            int added = 0, failed = 0;
            while (*names) {
                const char *comma = names;
                while (*comma && *comma != ',') comma++;
                int len = comma - names;
                if (len > 0 && len < ROOT_KW_NAME_LEN) {
                    memcpy(buf, names, len);
                    buf[len] = '\0';
                    if (root_kw_add(buf) == 0) added++; else failed++;
                }
                names = *comma ? comma + 1 : comma;
            }
            char result[128];
            snprintf(result, sizeof(result), "added: %d, failed: %d, total: %d",
                     added, failed, root_kw_count());
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "remove_hide_root:", 17) == 0) {
            const char *name = args + 17;
            int ret = root_kw_remove(name);
            char result[160];
            if (ret == 0)
                snprintf(result, sizeof(result), "removed '%s', total: %d", name, root_kw_count());
            else
                snprintf(result, sizeof(result), "remove failed: '%s' not found", name);
            compat_copy_to_user(out_msg, result, strlen(result) + 1);
            return 0;
        }
        if (strncmp(args, "list_hide_root", 14) == 0) {
            static char list_buf[2048];
            int count = root_kw_count();
            int offset = snprintf(list_buf, sizeof(list_buf),
                                  "total: %d (enabled=%d)\n", count, root_hide_enabled);
            if (count > 0) root_kw_dump(list_buf + offset, sizeof(list_buf) - offset);
            compat_copy_to_user(out_msg, list_buf, strlen(list_buf) + 1);
            return 0;
        }
        if (strncmp(args, "clear_hide_root", 15) == 0) {
            root_kw_clear();
            char msg[] = "all root_hide kw cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        if (strncmp(args, "reset_hide_root", 15) == 0) {
            root_kw_reset_defaults();
            char msg[64];
            snprintf(msg, sizeof(msg), "root_hide kw reset, total=%d", root_kw_count());
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }
        // ───── UID 豁免名单管理 ─────
        // add_exempt_self            把当前 caller uid 加入 (App 不需要知道自己 uid)
        // add_exempt_uid:<uid>       手工添加
        // remove_exempt_uid:<uid>    手工移除
        // list_exempt_uid            列表
        // clear_exempt_uid           清空
        if (strncmp(args, "add_exempt_self", 15) == 0) {
            int uid = current_uid_safe();
            char msg[80];
            if (uid < 0) {
                snprintf(msg, sizeof(msg), "add_exempt_self failed: cannot read current uid");
            } else {
                int r = root_exempt_uid_add(uid);
                snprintf(msg, sizeof(msg),
                         "add_exempt_self uid=%d %s, total=%d",
                         uid,
                         r == 0 ? "ok" : (r == -2 ? "full" : "err"),
                         root_exempt_uid_count());
            }
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }
        if (strncmp(args, "add_exempt_uid:", 15) == 0) {
            const char *p = args + 15;
            int uid = 0;
            while (*p >= '0' && *p <= '9') { uid = uid * 10 + (*p - '0'); p++; }
            int r = root_exempt_uid_add(uid);
            char msg[80];
            snprintf(msg, sizeof(msg), "add_exempt_uid %d %s, total=%d",
                     uid,
                     r == 0 ? "ok" : (r == -2 ? "full" : "err"),
                     root_exempt_uid_count());
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }
        if (strncmp(args, "remove_exempt_uid:", 18) == 0) {
            const char *p = args + 18;
            int uid = 0;
            while (*p >= '0' && *p <= '9') { uid = uid * 10 + (*p - '0'); p++; }
            int r = root_exempt_uid_remove(uid);
            char msg[80];
            snprintf(msg, sizeof(msg), "remove_exempt_uid %d %s, total=%d",
                     uid, r == 0 ? "ok" : "not_found",
                     root_exempt_uid_count());
            compat_copy_to_user(out_msg, msg, strlen(msg) + 1);
            return 0;
        }
        if (strncmp(args, "list_exempt_uid", 15) == 0) {
            char buf[512];
            int n = root_exempt_uid_count();
            int off = snprintf(buf, sizeof(buf), "total: %d\n", n);
            if (n > 0) root_exempt_uid_dump(buf + off, sizeof(buf) - off);
            compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
            return 0;
        }
        if (strncmp(args, "clear_exempt_uid", 16) == 0) {
            root_exempt_uid_clear();
            char msg[] = "all exempt_uid cleared";
            compat_copy_to_user(out_msg, msg, sizeof(msg));
            return 0;
        }
        // status_root 已在上方（"status" 之前）处理，此处不再重复
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
{   root_hide_uninstall();
    
    frida_hide_uninstall();
    klog("[svc] exit");
    return 0;
}

KPM_INIT(svc_init); // 装载回调
KPM_CTL0(svc_control0); // 控制0回调
KPM_CTL1(svc_control1); // 控制1回调
KPM_EXIT(svc_exit); // 卸载回调