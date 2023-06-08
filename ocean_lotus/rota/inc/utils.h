#ifndef UTILS_H_
#define UTILS_H_

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
int shm_create(char *mem);


/**
 * Helper function to convert integer value to string value
 * @param num, integer value to convert.
 * @return point to char memory.
 * */
 char *itoa(int num);

#endif // UTILS_H_
