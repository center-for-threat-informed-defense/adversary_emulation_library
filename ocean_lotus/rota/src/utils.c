#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

/**
 * Create a lock file to ensure one instance is running.
 * TODO - but how does this apply to the watch dog instances?
 * @param N/A
 * @return void
 * */
void create_lock();



/**
 * Create chared memory instance
 * @param mem a char pointer that contains the name of the shared memory instance.
 * @return integer value to be used as a file descriptor
 * */
int shm_create(char *mem) {

    if (!mem) {
        return -1;
    }

    // O_CREAT | O_EXCL | O_RDWR -> shared mem is created can be exectuded read/written to.
    // S_IRUSR | S_IWUSR -> allow users to read/write
    int fd = shm_open(mem, O_CREAT | O_APPEND | O_EXCL | O_RDWR,
                                 S_IRUSR | S_IWUSR);


    return fd;
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
