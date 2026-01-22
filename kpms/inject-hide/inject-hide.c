#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>


///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-inject-hide");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("Zskkk");

///< The description.
KPM_DESCRIPTION("inject-hide: init test");


/**
 * @brief initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long inject_hide_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("inject-hide init, event: %s, args: %s\n", event, args);
    pr_info("kernelpatch version: %x\n", kpver);

    //frida_hide_install();
    
    pr_info("inject-hide install\n");
    return 0;
}

static long inject_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("inject-hide control0, args: %s\n", args);
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long inject_hide_control1(void *a1, void *a2, void *a3)
{
    pr_info("inject-hide control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

static long inject_hide_exit(void *__user reserved)
{   
    //frida_hide_uninstall();
    pr_info("inject-hide exit\n");
    return 0;
}

KPM_INIT(inject_hide_init); // 装载回调
KPM_CTL0(inject_hide_control0); // 控制0回调
KPM_CTL1(inject_hide_control1); // 控制1回调
KPM_EXIT(inject_hide_exit); // 卸载回调