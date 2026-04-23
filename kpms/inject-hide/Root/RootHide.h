/*
 * @file   Root/RootHide.h
 * @brief  Root 痕迹隐藏模块（独立增量，不修改 FridHide 既有逻辑）。
 *
 * 设计说明
 * --------
 *   本模块不重复 hook 任何 syscall，全部复用 FridHide 已注册的
 *   openat / faccessat / getdents64 等 hook 链路。
 *   工作方式：
 *     1. install 时把内置的 root 关键词种子注入到 FridHide 的
 *        custom_hide_so[] 列表（通过 hide_so_add()）；
 *     2. 自动调用 dobby_hide_set_file_hide(1) 启用文件级隐藏；
 *     3. uninstall 时从 hide_so[] 中精确移除自己注入的关键词，
 *        不影响用户运行时另外添加的项。
 *
 *   同时维护一份独立的 root_kw[] 列表，用于：
 *     - 记录"哪些是本模块注入的"，方便干净卸载；
 *     - 提供独立的 control0 命令分发（add/list/remove/clear/reset）。
 *
 * 使用 (control0)
 * --------------
 *   enable_root_hide              启用 root 隐藏（自动同步注入种子并打开 file_hide）
 *   disable_root_hide             停用 root 隐藏（撤销注入，但保留 file_hide 状态由用户）
 *   add_hide_root:<kw>[,<kw>...]  追加 root 关键词
 *   remove_hide_root:<kw>         移除 root 关键词
 *   list_hide_root                列出当前 root 关键词
 *   clear_hide_root               清空 root 关键词（同步撤销注入）
 *   reset_hide_root               恢复默认种子
 *   status_root                   状态查询
 */
#ifndef ROOT_HIDE_H
#define ROOT_HIDE_H

// 容量：默认种子 ~160 + 用户扩充预留。
// 与 HIDE_SO_MAX_COUNT 匹配，避免注入时被拒。
#define ROOT_KW_MAX_COUNT 256
#define ROOT_KW_NAME_LEN  96

/* 模块生命周期 */
void root_hide_install(void);
void root_hide_uninstall(void);

/* 总开关：内部会同步 dobby_hide_set_file_hide() */
void root_hide_set(int enabled);
extern int root_hide_enabled;

/* 独立于全局 file_hide 的“仅针对 root 路径”过滤开关。
 * 开启后 hook 只拦截命中 root_kw[] 的 path，
 * 不影响用户通过 add_hide_so 添加的项。由 root_hide_set() 控制。 */
extern int root_file_hide_enabled;
int  is_root_kw_match(const char *path);

/* 关键词列表管理（独立于 FridHide 的 custom_hide_so，但会同步注入） */
int  root_kw_add(const char *name);
int  root_kw_remove(const char *name);
void root_kw_clear(void);
void root_kw_reset_defaults(void);
int  root_kw_count(void);
int  root_kw_dump(char *buf, int buf_len);

/* ──────────── UID 级豁免（exempt list） ────────────
 * 用途：被 root_hide 关键字误伤的"自己人" App（如 game 本身）
 *       把自己的 uid 注册进来，hook 链路视其为 trusted_caller，
 *       既看到所有 root 痕迹也不会被 file_hide 干扰。
 *
 * 与 sys_exempt 区别：
 *   sys_exempt 是按 [0, sys_exempt_uid_max) 范围豁免（系统进程）；
 *   exempt_uid 是显式名单，针对具体 App uid（10000+）。
 */
#define EXEMPT_UID_MAX_COUNT 16
int  root_exempt_uid_add(int uid);
int  root_exempt_uid_remove(int uid);
void root_exempt_uid_clear(void);
int  root_exempt_uid_count(void);
int  is_root_exempt_uid(int uid);                       /* 0=否, 1=是 */
int  root_exempt_uid_dump(char *buf, int buf_len);

#endif /* ROOT_HIDE_H */
