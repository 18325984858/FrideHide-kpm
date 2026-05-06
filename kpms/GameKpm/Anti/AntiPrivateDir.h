#ifndef GAMEKPM_ANTIPRIVATEDIR_H
#define GAMEKPM_ANTIPRIVATEDIR_H

/*
 * 游戏私有目录访问监控（仅观察，不拦截）
 *
 * 仅对目标进程 (is_target_current) 命中下列路径前缀时打日志：
 *   /data/data/com.tencent.tmgp.dfm/
 *   /data/user/0/com.tencent.tmgp.dfm/
 *   /data/data/com.tencent.tmgp.pubgmhd/
 *   /data/user/0/com.tencent.tmgp.pubgmhd/
 *
 * 重点关注子目录：
 *   files/ano_tmp/                — TPRT 检测规则缓存
 *   cache/                         — TerSafe 临时数据
 *
 * 不做任何修改、不短路 — 用于后续逆向收集行为数据。
 */

extern int g_private_dir_watch_enabled;
void anti_private_dir_set(int enabled);

int  anti_private_dir_install(void);
void anti_private_dir_uninstall(void);

#endif /* GAMEKPM_ANTIPRIVATEDIR_H */
