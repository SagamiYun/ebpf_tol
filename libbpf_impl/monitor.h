#ifndef __MONITOR_H
#define __MONITOR_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

enum event_type {
    EVENT_EXEC = 1,
    EVENT_FORK = 2,
    EVENT_READ = 3,
    EVENT_WRITE = 4
};

struct event {
    int pid;
    int ppid;
    unsigned int uid;
    int event_type;
    int fd;
    unsigned long long size;
    unsigned long long timestamp;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif
