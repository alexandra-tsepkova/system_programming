#include "fntf_detect.h"

void get_exe_path_of_process(pid_t pid, char *path){
    char path_in_proc[PATH_SIZE];
    snprintf(path_in_proc, PATH_SIZE, "/proc/%d/exe", pid);
    ssize_t exe_size = readlink(path_in_proc, path, PATH_SIZE);
    if (exe_size < 0){
        syslog(LOG_ERR,"can't get path to binary of malicious process!\n");
        exit(EXIT_FAILURE);
    }
    return;
}

void init_table(struct table_entry *table){
    for (int i = 0; i < TABLE_SIZE; ++i){
        table[i].pid = 0;
        table[i].accessed_files = 0;
    }
}

int find_entry(struct table_entry *table, pid_t pid){
    for (int i = 0; i < TABLE_SIZE; ++i){
        if (table[i].pid == pid){
            return i;
        }
    }
    return -1;
}

/* Read all available fanotify events from the file descriptor 'fd'. */
static void handle_events(int fd, struct table_entry *table)
{
    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[MAX_EVENTS];
    ssize_t len;
    char *path_exe;

    /* Loop while events can be read from fanotify file descriptor. */
    for (;;)
    {
        /* Read some events. */
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN)
        {
            syslog(LOG_ERR,"read event error!\n");
            exit(EXIT_FAILURE);
        }

        /* Check if end of available data reached. */
        if (len <= 0)
            break;
        /* Point to the first event in the buffer. */
        metadata = buf;

        /* Loop over all events in the buffer. */
        while (FAN_EVENT_OK(metadata, len))
        {
            if (metadata->fd >= 0)
            {
                /* Handle modification event. */
                if (metadata->mask & FAN_MODIFY)
                {
                    int index = find_entry(table, metadata->pid);
                    if (index == -1){
                        index = find_entry(table, 0);
                        table[index].pid = metadata->pid;
                    }
                    table[index].accessed_files += 1;
                    if ((table[index].accessed_files >= MAX_ACCESSED_FILES) && (metadata->pid > 8000)){
                        path_exe = (char*) malloc(PATH_SIZE * sizeof (char));
                        get_exe_path_of_process(metadata->pid, path_exe);
                        syslog(LOG_INFO,"Terminate potentially malicious process with pid %d and path to exe %s\n", metadata->pid, path_exe);
                        kill(metadata->pid, SIGTERM);
                        free(path_exe);
                    }
                }

                /* Close the file descriptor of the event. */
                if (close(metadata->fd) < 0){
                    syslog(LOG_ERR,"close event fd error!\n");
                    exit(EXIT_FAILURE);
                }
            }
            /* Advance to next event. */
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int run_detector()
{
    char buf;
    int fd, poll_num;
    nfds_t nfds;
    struct pollfd fds[2];
    struct pollfd fntf_fd;

    /* Create the file descriptor for accessing the fanotify API. */

    fd = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_NONBLOCK,
                       O_RDWR | O_LARGEFILE);
    if (fd == -1) {
        syslog(LOG_ERR,"fanotify_init error!\n");
        exit(EXIT_FAILURE);
    }

    /* Mark the mount for necessary events. */

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_MODIFY, AT_FDCWD, PATH) == -1) {
        syslog(LOG_ERR,"fanotify_mark error!\n");
        exit(EXIT_FAILURE);
    }

    /* Prepare for polling. */

    fntf_fd.fd = fd;
    fntf_fd.events = POLLIN;

    /* This is the loop to wait for incoming events. */

    syslog(LOG_INFO, "Listening for events.\n");
    struct table_entry table[TABLE_SIZE];
    init_table(table);

    while (1) {
        poll_num = poll(&fntf_fd, 1, -1);
        if (poll_num == -1) {
            if (errno == EINTR)     /* Interrupted by a signal */
                continue;           /* Restart poll() */

            syslog(LOG_ERR,"poll error!\n");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fntf_fd.revents & POLLIN) {

                /* Fanotify events are available. */

                handle_events(fd, table);
            }
        }
    }
}