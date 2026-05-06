#ifndef GAMEKPM_LOG_H
#define GAMEKPM_LOG_H

#include <linux/printk.h>

#define LOG_TAG "[GAMEKPM] "

extern int gk_log_enabled;
void gk_log_set(int enabled);

#define glog(fmt, ...) \
    do { if (gk_log_enabled) pr_info(LOG_TAG fmt "\n", ##__VA_ARGS__); } while (0)

#define glog_dbg(fmt, ...) \
    do { if (gk_log_enabled) pr_info(LOG_TAG "DBG: " fmt "\n", ##__VA_ARGS__); } while (0)

#define glog_err(fmt, ...) pr_err(LOG_TAG "ERROR: " fmt "\n", ##__VA_ARGS__)
#define glog_always(fmt, ...) pr_info(LOG_TAG fmt "\n", ##__VA_ARGS__)

#endif /* GAMEKPM_LOG_H */
