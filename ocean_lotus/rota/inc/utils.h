#ifndef UTILS_H_
#define UTILS_H_
#include <stdbool.h>
#include <stdbool.h>
#include <unistd.h>

/**
 * Create a lock file to ensure one instance is running.
 * TODO - but how does this apply to the watch dog instances?
 * @param N/A
 * @return void
 * */
void create_lock();

/**
 * @brief
 **/
bool self_delete(char *fpath);


bool write_to_file(char *fpath, char *data);

/**
 * Helper function to convert integer value to string value
 * @param num, integer value to convert.
 * @return point to char memory.
 * */
 char *itoa(int num);

#endif // UTILS_H_
