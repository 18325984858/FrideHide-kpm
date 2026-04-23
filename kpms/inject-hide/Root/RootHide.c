/*
 * @file   Root/RootHide.c
 * @brief  Root 痕迹隐藏实现。零 hook、零侵入：纯粹通过 FridHide
 *         已有的 hide_so / file_hide 通路实现路径级隐藏。
 *
 * 隐藏覆盖面（依赖 before_openat / before_faccessat 的 strstr 匹配）
 *   /system/bin/su, /system/xbin/su, /sbin/su, /data/adb/*
 *   /sbin/.magisk*, /data/adb/magisk*, magisk binary 名
 *   /data/adb/ksu*, /data/adb/ksud, KernelSU manager 私有路径
 *   /data/adb/ap*, APatch 私有路径
 *   /data/adb/modules/* (模块目录通常含 magisk/ksu/apatch 关键字)
 *   /data/adb/lsposed*, shamiko, zygisk, dobby, tricky 等
 *
 * 局限性（需要其他手段配合）
 *   - /proc/self/mounts、/proc/self/mountinfo 内容过滤需要 read hook
 *     （本模块未实现，建议结合 resetprop + APM systemless 卸载）；
 *   - getprop 伪装（ro.boot.verifiedbootstate 等）需要 APM 模块在
 *     post-fs-data.sh 用 resetprop 完成；
 *   - 硬件 Key Attestation 必须 Tricky Store + keybox。
 */
#include "RootHide.h"
#include "../Frid/FridHide.h"
#include "../Config/Log.h"

#include <linux/string.h>
#include <linux/kernel.h>

/* ────────────────────────────────────────────────────────────────── */
/*  默认 root 关键词种子（按类别分组）                                */
/*                                                                    */
/*  匹配机制：FridHide 使用 strstr 子串匹配 openat/faccessat 的 path  */
/*  参数。因此关键词需要：                                            */
/*    1. 足够长以避免误伤系统路径（禁止 "su"/"ap"/"ks" 这种）         */
/*    2. 具备唯一特征（如带 "/" 路径 或 完整工具名）                  */
/*    3. 配合 sys_exempt（UID<10000 豁免）避免系统链路被拦           */
/* ────────────────────────────────────────────────────────────────── */
static const char *const root_kw_defaults[] = {
    /* ── su 二进制路径 (完整路径以避免前缀误伤) ────────────────── */
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/product/bin/su",
    "/odm/bin/su",
    "/su/bin/su",
    "/magisk/.core/bin/su",
    "/data/local/tmp/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/cache/su",
    "/dev/su",
    "/su/xbin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU",
    "/system/app/Kinguser.apk",
    "/system/app/Kingroot",

    /* ── Magisk 家族 (Stable/Canary/Delta/Kitsune/Alpha) ─────── */
    "magisk",               /* 核心名 */
    "MagiskSU",
    "MagiskHide",
    "MagiskManager",
    "magiskhide",
    "magiskinit",
    "magiskboot",
    "magiskpolicy",
    "magisk.db",
    "magisk.log",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/cache/magisk.log",
    "/data/magisk",
    "/debug_ramdisk/.magisk",
    "/init.magisk.rc",
    "/mnt/vendor/persist/magisk",
    "kitsune",              /* Magisk Kitsune */
    "topjohnwu",            /* 官方包名根 */

    /* ── KernelSU 家族 (原版/Next/SukiSU/MKSU/RKSU) ─────────── */
    "KernelSU",
    "kernelsu",
    "ksud",
    "ksuwebui",
    "/data/adb/ksu",
    "/data/adb/ksud",
    "SukiSU",
    "sukisu",
    "MKSU",
    "RKSU",
    "KernelSUNext",
    "kernelsu_next",

    /* ── APatch / KernelPatch ─────────────────────────────── */
    "APatch",
    "apatch",
    "APatchManager",
    "KernelPatch",
    "kernelpatch",
    "kpatch",
    "/data/adb/ap",
    "/data/adb/ap/",
    "kpmmgr",

    /* ── 其他老旧 root 方案 ────────────────────────────────── */
    "SuperSU",              /* Chainfire */
    "supersu",
    "supolicy",
    "daemonsu",
    "KingRoot",
    "kingroot",
    "KingoRoot",
    "kingouser",
    "iRoot",
    "towelroot",
    "framaroot",
    "Superuser.apk",
    "superuser",
    "SuperUser",
    "OneClickRoot",
    "oneclickroot",
    "Z4Root",
    "z4root",
    "/system/bin/.ext/.su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/etc/.has_su_daemon",
    "/system/etc/.installed_su_daemon",
    "/system/xbin/daemonsu",
    "/system/xbin/busybox",
    "/cache/recovery/edify",

    /* ── Root 管理器包名 ──────────────────────────────────── */
    "com.topjohnwu.magisk",
    "io.github.huskydg.magisk",         /* Magisk Delta */
    "io.github.vvb2060.magisk",         /* Magisk Alpha */
    "me.weishu.kernelsu",
    "com.rifsxd.ksunext",
    "com.sukisu.ultra",
    "me.bmax.apatch",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.superuser",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",

    /* ── root 私有/模块目录 ────────────────────────────────── */
    "/data/adb/modules",
    "/data/adb/modules_update",
    "/data/adb/post-fs-data.d",
    "/data/adb/service.d",
    "/data/adb/boot-completed.d",
    "/data/adb/lsp",
    "/data/adb/lspd",
    "/data/adb/shamiko",
    "/data/adb/zygisksu",
    "/data/adb/tricky_store",

    /* ── Zygisk/隐藏框架 ──────────────────────────────────── */
    "Shamiko",
    "shamiko",
    "Zygisk",
    "zygisk",
    "ZygiskNext",
    "zygisknext",
    "zygiskd",
    "libzygisk",

    /* ── Hook 框架 (Xposed 家族) ───────────────────────────── */
    "LSPosed",
    "lsposed",
    "LSPatch",
    "lspatch",
    "EdXposed",
    "edxposed",
    "de.robv.android.xposed",
    "org.lsposed.manager",
    "org.lsposed.lspd",
    "org.lsposed.lspatch",
    "io.va.exposed",            /* VirtualXposed */
    "io.github.lsposed",
    "TaiChi",
    "me.weishu.exp",            /* TaiChi */
    "Dreamland",
    "top.canyie.dreamland",
    "riru",
    "Riru",
    "libriru",

    /* ── 隐藏反检测工具 ───────────────────────────────────── */
    "HideMyApplist",
    "hidemyapplist",
    "icu.nullptr.hidemyapplist",
    "Momo",
    "TrickyStore",
    "tricky_store",
    "TrickyAddon",
    "PlayIntegrityFix",
    "PlayIntegrityFork",
    "playintegrityfix",
    "UniversalSafetyNetFix",
    "usnf",
    "MagiskHidePropsConf",

    /* ── Frida / 调试器 / Dump 工具 ────────────────────────── */
    /*
     * 注意：这里只放"具备唯一特征"的完整工具名（含中划线/特定后缀）
     * 等。**不要**放裸短名（"frida" / "dobby" / "gadget" / "cydia" 等）
     * 因为它们极易与用户 App 包名/SO 名（如 com.example.dobbyproject、
     * libdobbyproject.so、含 "frida" 的研究工具 App）冲突，导致
     * App 自身的 base.apk / lib / data 目录被误拦无法启动。
     * 如需隐藏 Frida/Dobby Hook 痕迹，请通过 add_hide_so 主动添加
     * 到 hide_so 列表（受 file_hide_enabled 控制），不应放进
     * root_hide 默认种子。
     */
    "frida-agent",
    "frida-server",
    "fridaserver",
    "re.frida.server",
    "gum-js-loop",
    "linjector",
    "objection",
    "libsubstrate",
    "cydia.substrate",

    /* ── VPN/代理/虚拟化类 (可选，默认不开注释) ───────────── */
    /* "com.lbe.parallel",          Parallel Space          */
    /* "com.excelliance.dualaid",   DualSpace               */
    /* "com.ljmobile.applock",                              */

    NULL
};

/* ────────────────────────────────────────────────────────────────── */
/*  内部状态                                                          */
/* ────────────────────────────────────────────────────────────────── */
int root_hide_enabled = 0;
int root_file_hide_enabled = 0;       /* 仅匹配 root_kw[] 的路径过滤开关 */

/* 本模块注入到 FridHide hide_so 列表的关键词副本，用于精确撤销。 */
static char root_kw[ROOT_KW_MAX_COUNT][ROOT_KW_NAME_LEN];
static int  root_kw_n = 0;
/* 标记某关键词是否已成功注入到 FridHide 的 hide_so 列表 */
static char root_kw_injected[ROOT_KW_MAX_COUNT];

/* ────────────────────────────────────────────────────────────────── */
/*  内部辅助                                                          */
/* ────────────────────────────────────────────────────────────────── */
static int root_kw_index(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < root_kw_n; i++) {
        if (strcmp(root_kw[i], name) == 0) return i;
    }
    return -1;
}

/* 将 root_kw[i] 注入 FridHide 的 hide_so 列表 */
static void root_kw_inject_one(int i)
{
    if (i < 0 || i >= root_kw_n) return;
    if (root_kw_injected[i]) return;
    int rc = hide_so_add(root_kw[i]);
    /* rc == 0 成功；rc == -3 已存在（被用户先添加过）。两种情况都不再
       由我们撤销，所以只在 rc == 0 时标记为"我们注入的"。 */
    if (rc == 0) {
        root_kw_injected[i] = 1;
    } else {
        root_kw_injected[i] = 0;
        if (rc == -2) {
            klog("[root_hide] hide_so list full, cannot inject '%s'", root_kw[i]);
        }
    }
}

/* 将 root_kw[i] 从 FridHide 的 hide_so 列表中撤销 */
static void root_kw_revoke_one(int i)
{
    if (i < 0 || i >= root_kw_n) return;
    if (!root_kw_injected[i]) return;
    hide_so_remove(root_kw[i]);
    root_kw_injected[i] = 0;
}

static void root_kw_inject_all(void)
{
    for (int i = 0; i < root_kw_n; i++) root_kw_inject_one(i);
}

static void root_kw_revoke_all(void)
{
    for (int i = 0; i < root_kw_n; i++) root_kw_revoke_one(i);
}

/* ────────────────────────────────────────────────────────────────── */
/*  对外 API                                                          */
/* ────────────────────────────────────────────────────────────────── */
int root_kw_add(const char *name)
{
    if (!name || !name[0]) return -1;
    if (strlen(name) >= ROOT_KW_NAME_LEN) return -4;
    if (root_kw_n >= ROOT_KW_MAX_COUNT) return -2;
    if (root_kw_index(name) >= 0) return -3;

    int idx = root_kw_n++;
    strncpy(root_kw[idx], name, ROOT_KW_NAME_LEN - 1);
    root_kw[idx][ROOT_KW_NAME_LEN - 1] = '\0';
    root_kw_injected[idx] = 0;

    if (root_hide_enabled) root_kw_inject_one(idx);
    klog("[root_hide] kw_add: '%s', total=%d", name, root_kw_n);
    return 0;
}

int root_kw_remove(const char *name)
{
    int idx = root_kw_index(name);
    if (idx < 0) return -2;

    /* 撤销在 FridHide 列表中的注入 */
    root_kw_revoke_one(idx);

    /* 末尾元素移到当前位置 */
    int last = root_kw_n - 1;
    if (idx != last) {
        memcpy(root_kw[idx], root_kw[last], ROOT_KW_NAME_LEN);
        root_kw_injected[idx] = root_kw_injected[last];
    }
    root_kw[last][0] = '\0';
    root_kw_injected[last] = 0;
    root_kw_n--;

    klog("[root_hide] kw_remove: '%s', total=%d", name, root_kw_n);
    return 0;
}

void root_kw_clear(void)
{
    root_kw_revoke_all();
    for (int i = 0; i < root_kw_n; i++) {
        root_kw[i][0] = '\0';
        root_kw_injected[i] = 0;
    }
    root_kw_n = 0;
    klog("[root_hide] kw_clear");
}

void root_kw_reset_defaults(void)
{
    root_kw_clear();
    for (int i = 0; root_kw_defaults[i] != NULL; i++) {
        if (root_kw_n >= ROOT_KW_MAX_COUNT) break;
        const char *s = root_kw_defaults[i];
        if (!s || !s[0]) continue;
        if (strlen(s) >= ROOT_KW_NAME_LEN) continue;
        strncpy(root_kw[root_kw_n], s, ROOT_KW_NAME_LEN - 1);
        root_kw[root_kw_n][ROOT_KW_NAME_LEN - 1] = '\0';
        root_kw_injected[root_kw_n] = 0;
        root_kw_n++;
    }
    if (root_hide_enabled) root_kw_inject_all();
    klog("[root_hide] kw_reset_defaults, total=%d", root_kw_n);
}

int root_kw_count(void) { return root_kw_n; }

int root_kw_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int offset = 0;
    for (int i = 0; i < root_kw_n && offset < buf_len - 1; i++) {
        int n = snprintf(buf + offset, buf_len - offset, "%s%s\n",
                         root_kw[i],
                         root_kw_injected[i] ? "" : " [pending]");
        if (n < 0 || n >= buf_len - offset) break;
        offset += n;
    }
    if (offset == 0) buf[0] = '\0';
    return offset;
}

void root_hide_set(int enabled)
{
    int prev = root_hide_enabled;
    root_hide_enabled = enabled ? 1 : 0;

    if (root_hide_enabled && !prev) {
        /* 启用：只打开 root 专属的路径过滤开关；不动全局 file_hide，
         * 也不再把 168 个 root 关键字塞进 custom_hide_so[]，避免污染
         * 用户通过 add_hide_so 维护的列表。 */
        root_file_hide_enabled = 1;
        klog("[root_hide] enabled, root_file_hide=on, kw=%d (custom_hide_so untouched)",
             root_kw_n);
    } else if (!root_hide_enabled && prev) {
        /* 停用：仅关闭专属开关；用户的 file_hide / hide_so 不动 */
        root_file_hide_enabled = 0;
        klog("[root_hide] disabled, root_file_hide=off");
    }
}

/* 路径匹配：
 *   - 关键字以 '/' 开头  → 视为完整路径模式，整路径子串匹配
 *   - 其他（裸名）       → 仅在 basename（最后一个 '/' 之后）里匹配，
 *                          且要求 strlen(kw) >= 5，避免 4 字以内短串
 *                          (ksud/MKSU/RKSU/Riru/usnf 等) 在常见
 *                          路径中段误中导致所有 App 启动被拦截。
 *
 * 这样 /data/app/.../base.apk、/system/lib64/libxxx.so 这种"路径中段"
 * 含 magisk/dobby/frida/apatch 子串的情形不再被屏蔽；只有当**文件名**
 * 本身命中关键字（例如 magiskd、libdobby.so、frida-server）才被拦。
 */
int is_root_kw_match(const char *path)
{
    if (!path || !root_file_hide_enabled) return 0;

    /* 取 basename：最后一个 '/' 之后 */
    const char *base = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/') base = p + 1;
    }

    for (int i = 0; i < root_kw_n; i++) {
        const char *kw = root_kw[i];
        if (!kw[0]) continue;

        if (kw[0] == '/') {
            /* 完整路径模式 */
            if (strstr(path, kw)) {
                klog("[root_hide] match path: kw='%s' path='%s'", kw, path);
                return 1;
            }
        } else {
            /* 裸名模式：只在 basename 匹配 */
            if (strlen(kw) < 5) continue;        /* 太短，跳过 */
            if (strstr(base, kw)) {
                klog("[root_hide] match basename: kw='%s' base='%s' path='%s'",
                     kw, base, path);
                return 1;
            }
        }
    }
    return 0;
}

void root_hide_install(void)
{
    /* 仅准备数据，不主动启用。由 control0 "enable_root_hide" 触发。 */
    root_kw_reset_defaults();
    klog("[root_hide] install: %d default kw seeded (disabled)", root_kw_n);
}

void root_hide_uninstall(void)
{
    /* 卸载时确保不残留：撤销注入并关闭专属开关 */
    if (root_hide_enabled) {
        root_kw_revoke_all();
        root_hide_enabled = 0;
        root_file_hide_enabled = 0;
    }
    /* 不清空 root_kw[]，方便日志诊断；reload 模块时会被 install 重置 */
    klog("[root_hide] uninstall");
}

/* ──────────── UID 豁免列表实现 ──────────── */
static int exempt_uids[EXEMPT_UID_MAX_COUNT];
static int exempt_uid_n = 0;

int root_exempt_uid_count(void) { return exempt_uid_n; }

int is_root_exempt_uid(int uid)
{
    if (uid < 0) return 0;
    for (int i = 0; i < exempt_uid_n; i++) {
        if (exempt_uids[i] == uid) return 1;
    }
    return 0;
}

int root_exempt_uid_add(int uid)
{
    if (uid < 0) return -1;
    if (is_root_exempt_uid(uid)) return 0;        /* 幂等 */
    if (exempt_uid_n >= EXEMPT_UID_MAX_COUNT) {
        klog("[root_hide] exempt_uid full (%d)", EXEMPT_UID_MAX_COUNT);
        return -2;
    }
    exempt_uids[exempt_uid_n++] = uid;
    klog("[root_hide] exempt_uid_add: %d, total=%d", uid, exempt_uid_n);
    return 0;
}

int root_exempt_uid_remove(int uid)
{
    for (int i = 0; i < exempt_uid_n; i++) {
        if (exempt_uids[i] == uid) {
            for (int j = i + 1; j < exempt_uid_n; j++)
                exempt_uids[j - 1] = exempt_uids[j];
            exempt_uid_n--;
            klog("[root_hide] exempt_uid_remove: %d, total=%d", uid, exempt_uid_n);
            return 0;
        }
    }
    return -1;
}

void root_exempt_uid_clear(void)
{
    exempt_uid_n = 0;
    klog("[root_hide] exempt_uid_clear");
}

int root_exempt_uid_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int offset = 0;
    for (int i = 0; i < exempt_uid_n && offset < buf_len - 1; i++) {
        int n = snprintf(buf + offset, buf_len - offset, "%d\n", exempt_uids[i]);
        if (n < 0 || n >= buf_len - offset) break;
        offset += n;
    }
    if (offset == 0) buf[0] = '\0';
    return offset;
}
