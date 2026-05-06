#ifndef GAMEKPM_TARGET_H
#define GAMEKPM_TARGET_H

/*
 * GameKpm 目标进程判定
 *
 * 两层匹配（任一命中即视为目标）：
 *   1. comm 前缀匹配（task->comm 16 字节）— 适合 zygote 初期 comm 还是包名时
 *   2. tgid 直接匹配 — 适合像 UE4/Unity 那样自改 comm 为 "MainThread-UE4" 的进程
 *
 * 实际使用时通常 1 命中一次后 game_reload.sh 立刻把 pid 用 add_target_pid
 * 注册进 2，这样所有线程（comm 各异）的 syscall 都能被拦截。
 */

#define GK_TARGET_MAX_COUNT  8
#define GK_TARGET_NAME_LEN   16   /* 必须 ≤ TASK_COMM_LEN(16)，含 NUL */
#define GK_TARGET_PID_MAX    16   /* 同时跟踪的 tgid 数 */
#define GK_TARGET_FULL_MAX   8    /* 完整包名 */
#define GK_TARGET_FULL_LEN   80   /* 包名最长 80 字节 */

void target_seed_defaults(void);

/* ── comm 前缀列表 ── */
int  target_add(const char *prefix);
int  target_remove(const char *prefix);
void target_clear(void);
int  target_count(void);
int  target_dump(char *buf, int buf_len);

/* ── tgid 列表 ── */
int  target_add_pid(int tgid);
int  target_remove_pid(int tgid);
void target_clear_pid(void);
int  target_count_pid(void);
int  target_dump_pid(char *buf, int buf_len);

/* ── 完整包名列表（prctl PR_SET_NAME 路径用） ── */
int  target_add_full(const char *name);
int  target_remove_full(const char *name);
void target_clear_full(void);
int  target_count_full(void);
int  target_dump_full(char *buf, int buf_len);
int  is_target_fullname(const char *name);

/* 判定当前 task 是否命中（comm 前缀 OR tgid 匹配） */
int is_target_current(void);

/* 直接对外部 comm 字符串判定（仅 comm 前缀路径） */
int is_target_comm(const char *comm);

#endif /* GAMEKPM_TARGET_H */

