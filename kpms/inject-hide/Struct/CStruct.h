#ifndef CSTRUCT_H
#define CSTRUCT_H


typedef struct seq_file {
	char *buf;
	unsigned long size;
	unsigned long from;
	unsigned long count;
	unsigned long pad_until;
	long long index;
	long long read_pos;
};

struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;     
    unsigned int sin_addr;     
    char sin_zero[8];
};

#endif //CSTRUCT_H