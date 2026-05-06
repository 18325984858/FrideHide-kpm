#include "Target.h"
#include "Log.h"

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <ksyms.h>

static char g_targets[GK_TARGET_MAX_COUNT][GK_TARGET_NAME_LEN];
static int  g_target_count = 0;

/* tgid 列表 */
static int g_target_pids[GK_TARGET_PID_MAX];
static int g_target_pid_count = 0;

/* 完整包名列表 — prctl(PR_SET_NAME) 路径精确匹配 */
static char g_target_fulls[GK_TARGET_FULL_MAX][GK_TARGET_FULL_LEN];
static int  g_target_full_count = 0;

/* 解析 current 的 comm — 复用内核符号，避免直接读 task_struct.comm 的偏移依赖 */
typedef char *(*get_task_comm_fn)(char *buf, size_t buf_size, struct task_struct *tsk);
static get_task_comm_fn _get_task_comm = 0;

/* current->tgid 通过偏移读 — 不同内核可能不同，运行期 kallsyms 不暴露 task_struct，
   退而求其次：用 current 指针 + 在 inject-hide 里见过的偏移做硬编码会脆弱。
   这里走"用 ksym 拿 task_pid_nr / task_tgid_nr"路径。 */
typedef int (*task_tgid_nr_fn)(struct task_struct *tsk);
static task_tgid_nr_fn _task_tgid_nr = 0;

/* 备用：__task_pid_nr_ns(task, type, ns) — KP demo 中使用过 */
struct pid_namespace;
typedef int (*task_pid_nr_ns_fn)(struct task_struct *task, int type, struct pid_namespace *ns);
static task_pid_nr_ns_fn _task_pid_nr_ns = 0;
#define PIDTYPE_TGID 1

static int find_index(const char *prefix)
{
    for (int i = 0; i < g_target_count; i++) {
        if (strcmp(g_targets[i], prefix) == 0) return i;
    }
    return -1;
}

static int find_pid_index(int tgid)
{
    for (int i = 0; i < g_target_pid_count; i++) {
        if (g_target_pids[i] == tgid) return i;
    }
    return -1;
}

void target_seed_defaults(void)
{
    if (!_get_task_comm) {
        _get_task_comm = (get_task_comm_fn)kallsyms_lookup_name("__get_task_comm");
        glog("__get_task_comm = %llx", (unsigned long long)_get_task_comm);
    }
    if (!_task_tgid_nr) {
        _task_tgid_nr = (task_tgid_nr_fn)kallsyms_lookup_name("task_tgid_nr");
        glog("task_tgid_nr = %llx", (unsigned long long)_task_tgid_nr);
    }
    if (!_task_pid_nr_ns) {
        _task_pid_nr_ns = (task_pid_nr_ns_fn)kallsyms_lookup_name("__task_pid_nr_ns");
        glog("__task_pid_nr_ns = %llx", (unsigned long long)_task_pid_nr_ns);
    }

    /* 默认 comm 前缀：腾讯包名（zygote 初始 comm；UE4/Unity 之后会改名，
       届时由 game_reload.sh 通过 add_target_pid 注册 tgid） */
    target_add("com.tencent.tmg");
    /* UE4 主线程通用名（命中后 game_reload.sh 会立即注册 tgid） */
    target_add("MainThread-UE4");

    /* 完整包名 — prctl(PR_SET_NAME) 路径精确匹配，零误伤 */
    target_add_full("com.tencent.tmgp.dfm");
    target_add_full("com.tencent.tmgp.pubgmhd");
}

/* ───── comm 前缀列表 ───── */
int target_add(const char *prefix)
{
    if (!prefix || !*prefix) return -1;
    int len = strlen(prefix);
    if (len >= GK_TARGET_NAME_LEN) {
        glog_err("target_add: '%s' too long (max %d)", prefix, GK_TARGET_NAME_LEN - 1);
        return -2;
    }
    if (find_index(prefix) >= 0) {
        glog("target_add: '%s' already exists", prefix);
        return -3;
    }
    if (g_target_count >= GK_TARGET_MAX_COUNT) {
        glog_err("target_add: list full (%d)", GK_TARGET_MAX_COUNT);
        return -4;
    }
    strncpy(g_targets[g_target_count], prefix, GK_TARGET_NAME_LEN - 1);
    g_targets[g_target_count][GK_TARGET_NAME_LEN - 1] = '\0';
    g_target_count++;
    glog("target_add: '%s' total=%d", prefix, g_target_count);
    return 0;
}

int target_remove(const char *prefix)
{
    if (!prefix) return -1;
    int idx = find_index(prefix);
    if (idx < 0) return -2;
    if (idx < g_target_count - 1) {
        memcpy(g_targets[idx], g_targets[g_target_count - 1], GK_TARGET_NAME_LEN);
    }
    g_targets[g_target_count - 1][0] = '\0';
    g_target_count--;
    glog("target_remove: '%s' total=%d", prefix, g_target_count);
    return 0;
}

void target_clear(void)
{
    for (int i = 0; i < g_target_count; i++) g_targets[i][0] = '\0';
    g_target_count = 0;
    glog("target_clear");
}

int target_count(void) { return g_target_count; }

int target_dump(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < g_target_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%s\n", g_targets[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

/* ───── tgid 列表 ───── */
int target_add_pid(int tgid)
{
    if (tgid <= 0) return -1;
    if (find_pid_index(tgid) >= 0) return -3;
    if (g_target_pid_count >= GK_TARGET_PID_MAX) return -4;
    g_target_pids[g_target_pid_count++] = tgid;
    glog("target_add_pid: %d total=%d", tgid, g_target_pid_count);
    return 0;
}

int target_remove_pid(int tgid)
{
    int idx = find_pid_index(tgid);
    if (idx < 0) return -2;
    if (idx < g_target_pid_count - 1) {
        g_target_pids[idx] = g_target_pids[g_target_pid_count - 1];
    }
    g_target_pid_count--;
    glog("target_remove_pid: %d total=%d", tgid, g_target_pid_count);
    return 0;
}

void target_clear_pid(void) { g_target_pid_count = 0; glog("target_clear_pid"); }
int  target_count_pid(void) { return g_target_pid_count; }

int target_dump_pid(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < g_target_pid_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%d\n", g_target_pids[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

/* ───── 判定 ───── */
int is_target_comm(const char *comm)
{
    if (!comm || !*comm) return 0;
    for (int i = 0; i < g_target_count; i++) {
        const char *p = g_targets[i];
        int len = strlen(p);
        if (len == 0) continue;
        if (strncmp(comm, p, len) == 0) return 1;
    }
    return 0;
}

int is_target_current(void)
{
    /* tgid 路径优先 — 一旦命中就不用读 comm */
    int tgid = -1;
    if (g_target_pid_count > 0 || g_target_count > 0) {
        if (_task_tgid_nr) {
            tgid = _task_tgid_nr(current);
        } else if (_task_pid_nr_ns) {
            tgid = _task_pid_nr_ns(current, PIDTYPE_TGID, 0);
        }
        if (tgid > 0 && find_pid_index(tgid) >= 0) return 1;
    }

    /* comm 前缀路径 */
    if (g_target_count == 0) return 0;
    /* _get_task_comm 已在 target_seed_defaults() init 时解析；
       这里不再做 lazy lookup —— 在 hot path 调 kallsyms_lookup_name
       并写全局变量会触发并发读 half-set 指针 → CPU 跳无效地址 → Oops */
    if (!_get_task_comm) return 0;
    char comm[16];
    _get_task_comm(comm, sizeof(comm), current);
    comm[sizeof(comm) - 1] = '\0';

    if (!is_target_comm(comm)) return 0;

    /* comm 命中：自动把当前 tgid 加进 pid 列表（幂等 + 容量自管）
       这样下一次同进程的任意线程（即使 comm 已被 UE4 改成 RHI/ChunkPrefetcher 等）
       都能直接走 tgid 路径命中，无需用户态 add_target_pid。 */
    if (tgid > 0 && find_pid_index(tgid) < 0) {
        if (g_target_pid_count < GK_TARGET_PID_MAX) {
            g_target_pids[g_target_pid_count++] = tgid;
            glog("auto target_add_pid: %d (comm=%s) total=%d", tgid, comm, g_target_pid_count);
        }
    }
    return 1;
}


/* ───── 完整包名列表 ───── */
static int find_full_index(const char *name)
{
    for (int i = 0; i < g_target_full_count; i++) {
        if (strcmp(g_target_fulls[i], name) == 0) return i;
    }
    return -1;
}

int target_add_full(const char *name)
{
    if (!name || !*name) return -1;
    int len = strlen(name);
    if (len >= GK_TARGET_FULL_LEN) return -2;
    if (find_full_index(name) >= 0) return -3;
    if (g_target_full_count >= GK_TARGET_FULL_MAX) return -4;
    strncpy(g_target_fulls[g_target_full_count], name, GK_TARGET_FULL_LEN - 1);
    g_target_fulls[g_target_full_count][GK_TARGET_FULL_LEN - 1] = '\0';
    g_target_full_count++;
    glog("target_add_full: '%s' total=%d", name, g_target_full_count);
    return 0;
}

int target_remove_full(const char *name)
{
    int idx = find_full_index(name);
    if (idx < 0) return -2;
    if (idx < g_target_full_count - 1) {
        memcpy(g_target_fulls[idx], g_target_fulls[g_target_full_count - 1], GK_TARGET_FULL_LEN);
    }
    g_target_full_count--;
    glog("target_remove_full: '%s' total=%d", name, g_target_full_count);
    return 0;
}

void target_clear_full(void)        { g_target_full_count = 0; glog("target_clear_full"); }
int  target_count_full(void)        { return g_target_full_count; }

int target_dump_full(char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return -1;
    int off = 0;
    for (int i = 0; i < g_target_full_count && off < buf_len - 1; i++) {
        int n = snprintf(buf + off, buf_len - off, "%s\n", g_target_fulls[i]);
        if (n < 0 || n >= buf_len - off) break;
        off += n;
    }
    if (off == 0 && buf_len > 0) buf[0] = '\0';
    return off;
}

int is_target_fullname(const char *name)
{
    if (!name || !*name) return 0;
    /* 精确匹配 */
    if (find_full_index(name) >= 0) return 1;
    /* 前缀匹配：__set_task_comm 路径会把完整包名截断到 15 字节传进来，
       所以 list 中的 "com.tencent.tmgp.dfm" 与 "com.tencent.tmg"（截断版）
       要都能匹配。比较 min(strlen(name), strlen(list_item))。 */
    int n_in = strlen(name);
    if (n_in == 0) return 0;
    for (int i = 0; i < g_target_full_count; i++) {
        const char *p = g_target_fulls[i];
        int n_p = strlen(p);
        int m = n_in < n_p ? n_in : n_p;
        if (m < 8) continue;     /* 至少 8 字节匹配避免误伤 */
        if (strncmp(name, p, m) == 0) return 1;
    }
    return 0;
}
