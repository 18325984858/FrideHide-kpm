#ifndef CSTRUCT_H
#define CSTRUCT_H
#include <ktypes.h>

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;

};
#endif //CSTRUCT_H