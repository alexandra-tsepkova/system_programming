#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"

#define MAX_EVENTS 200
#define MAX_ACCESSED_FILES 1
#define TABLE_SIZE 300


#define PID_FILE_PATH "/run/my_detector.pid"
#define PATH_SIZE 512

struct table_entry{
    pid_t pid;
    int accessed_files;
};

void get_exe_path_of_process(pid_t pid, char *path);

void init_table(struct table_entry *table);

int find_entry(struct table_entry *table, pid_t pid);

static void handle_events(int fd, struct table_entry *table);

int run_detector();