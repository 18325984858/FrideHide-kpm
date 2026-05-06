#ifndef GAMEKPM_ANTIMEM_H
#define GAMEKPM_ANTIMEM_H

extern int g_mincore_lie_enabled;
void anti_mem_set_mincore(int enabled);

int  anti_mem_install(void);
void anti_mem_uninstall(void);

#endif /* GAMEKPM_ANTIMEM_H */
