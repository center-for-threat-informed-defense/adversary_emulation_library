#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>

#include "c2_commands.h"


void c2_loop(){
    int sleepy_time = 3;

    while (1) {
        printf("(%d) In c2 loop...\n", getpid());


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


void c2_upload_device_info() {
    // Netlab 360 make this look like populating a uname struct, /etc/os-relase/etc...
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
