#ifndef UTILS_H_
#define UTILS_H_

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
 *
 * @brief
 *
 **/
bool self_delete(char *fpath);

#endif // UTILS_H_
