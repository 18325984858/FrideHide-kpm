#ifndef CSTRUCT_H
#define CSTRUCT_H



typedef struct seq_file {
	char *buf;
	unsigned int size;
	unsigned int from;
	unsigned int count;
	unsigned int pad_until;
	long long index;
	long long read_pos;
}seq_file;


#endif //CSTRUCT_H