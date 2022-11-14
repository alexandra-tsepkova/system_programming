#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>

#define MAX_EVENTS 200
#define MAX_ACCESSED_FILES 5
#define TABLE_SIZE 300

struct table_entry{
    pid_t pid;
    int accessed_files;
};

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

    /* Loop while events can be read from fanotify file descriptor. */
    for (;;)
    {
        /* Read some events. */
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN)
        {
            perror("read event error!\n");
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
                        printf("Terminate potentially malicious process with pid %d\n", metadata->pid);
                        kill(metadata->pid, SIGTERM);
                    }
                }

                /* Close the file descriptor of the event. */
                if (close(metadata->fd) < 0){
                    perror("close event fd error!\n");
                    exit(EXIT_FAILURE);
                }
            }
            /* Advance to next event. */
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int main(int argc, char *argv[])
{
    printf("%s\n", argv[1]);
    char buf;
    int fd, poll_num;
    nfds_t nfds;
    struct pollfd fds[2];

    /* Check mount point is supplied. */

    if (argc != 2) {
        fprintf(stderr, "Usage: %s MOUNT\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *pathname = argv[1];

    printf("Press enter key to terminate.\n");

    /* Create the file descriptor for accessing the fanotify API. */

    fd = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_NONBLOCK,
                       O_RDWR | O_LARGEFILE);
    if (fd == -1) {
        perror("fanotify_init error!\n");
        exit(EXIT_FAILURE);
    }

    /* Mark the mount for necessary events. */

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_MODIFY, AT_FDCWD, pathname) == -1) {
        perror("fanotify_mark error!\n");
        exit(EXIT_FAILURE);
    }

    /* Prepare for polling. */

    nfds = 2;

    fds[0].fd = STDIN_FILENO;       /* Console input */
    fds[0].events = POLLIN;

    fds[1].fd = fd;                 /* Fanotify input */
    fds[1].events = POLLIN;

    /* This is the loop to wait for incoming events. */

    printf("Listening for events.\n");
    struct table_entry table[TABLE_SIZE];
    init_table(table);

    while (1) {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR)     /* Interrupted by a signal */
                continue;           /* Restart poll() */

            perror("poll error!\n");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {

                /* Console input is available: empty stdin and quit. */

                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN) {


                /* Fanotify events are available. */

                handle_events(fd, table);
            }
        }
    }

    printf("Listening for events stopped.\n");
    exit(EXIT_SUCCESS);
}