#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// this is loaded via dlsym.
// the argument to the rota_c2_run_plugin_1 command
extern void update(void) {

    system("mount > /tmp/mount.txt");
}
