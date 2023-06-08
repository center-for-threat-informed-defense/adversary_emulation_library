#include <unistd.h>
#include <string.h>

#include "utils.h"

int main(int argc, char *argv[]) {

    pid_t id = getuid();
    int pid = getpid();

    char *fpath; // filepath

    // TODO: session_dbus_file_write

    // Creating shared mem
    shm_create("tmpmem");

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

    return 0;
}
