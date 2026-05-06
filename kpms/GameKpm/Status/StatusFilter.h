#ifndef GAMEKPM_STATUSFILTER_H
#define GAMEKPM_STATUSFILTER_H

extern int g_status_filter_enabled;
void status_filter_set(int enabled);

int  status_filter_install(void);
void status_filter_uninstall(void);

#endif /* GAMEKPM_STATUSFILTER_H */
