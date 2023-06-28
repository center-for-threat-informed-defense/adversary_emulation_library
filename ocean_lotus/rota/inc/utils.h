#ifndef UTILS_H_
#define UTILS_H_
#include <stdbool.h>
#include <stdbool.h>
#include <unistd.h>

/**
 * Create a lock file to ensure one instance is running.
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
 *@brief helper function for recursively creating directories
 *@param home, boolean value to indicate to prepend $HOME to the fpath
 *@param fpath, FULL file path to create
 *@param mode, integer value for permissions w/ mkdir
 *
 **/
void _mkdir(bool home, char *fpath, int mode);


#endif // UTILS_H_
