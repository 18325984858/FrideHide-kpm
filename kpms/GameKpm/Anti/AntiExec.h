#ifndef GAMEKPM_ANTIEXEC_H
#define GAMEKPM_ANTIEXEC_H

extern int g_exec_block_enabled;
extern int g_inotify_swallow_enabled;

void anti_exec_set_block(int enabled);
void anti_exec_set_inotify(int enabled);

int  anti_exec_install(void);
void anti_exec_uninstall(void);

#endif /* GAMEKPM_ANTIEXEC_H */
