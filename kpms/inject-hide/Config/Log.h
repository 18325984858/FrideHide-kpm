#ifndef LOG_H
#define LOG_H

#include <linux/printk.h>

// 定义模块日志标志（前缀）
#define LOG_TAG "[SFK] "

// 封装 klog 宏：自动添加前缀和换行符
#define klog(fmt, ...) pr_info(LOG_TAG fmt "\n", ##__VA_ARGS__)

// 如果需要错误级别，可以单独定义一个
#define klog_err(fmt, ...) pr_err(LOG_TAG "ERROR: " fmt "\n", ##__VA_ARGS__)


#endif //LOG_H