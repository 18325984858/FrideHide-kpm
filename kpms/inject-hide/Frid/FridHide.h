#ifndef FRIDA_HIDE_H
#define FRIDA_HIDE_H

#include "../Struct/CStruct.h"


void frida_hide_install(void);
void frida_hide_uninstall(void);

static int is_hiden_module(struct seq_file *m);
static void *memmem_local(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);



#endif //FRIDA_HIDE_H