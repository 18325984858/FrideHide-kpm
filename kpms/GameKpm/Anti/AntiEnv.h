#ifndef GAMEKPM_ANTIENV_H
#define GAMEKPM_ANTIENV_H

extern int g_uname_spoof_enabled;
void anti_env_set_uname(int enabled);

int  anti_env_install(void);
void anti_env_uninstall(void);

#endif /* GAMEKPM_ANTIENV_H */
