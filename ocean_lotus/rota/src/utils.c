#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <unistd.h>

/**
 * Create a lock file to ensure one instance is running.
 * TODO - but how does this apply to the watch dog instances?
 * @param N/A
 * @return void
 * */
void create_lock();



/**
 * wrapper function to create data from shared memory instance
 * Reference: https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
 * @param identifier name of shared mem file.
 * @param size number of bytes to read.
 * */
int shm_get(int identifier, int size) {

    // NULL check
    if (!identifier) {
        return -1;
    }

    // Note - this method *does not* create a file artifact in /dev/shm
    return shmget(identifier, size, 0x3b6);
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
    }

    free(tmpFileBuff);

    return filePathBuff;
}


/**
 * Helper function to convert integer value to string value
 * - NOTE, don't forget to free this memory :)
 * @param num, integer value to convert.
 * @return point to char memory.
 * */
char *itoa(int num) {

    char *c_num = malloc(sizeof(num));
    sprintf(c_num, "%d", num);

    return c_num;
}
