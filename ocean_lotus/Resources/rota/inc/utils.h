#ifndef UTILS_H_
#define UTILS_H_
#include <stdbool.h>

// create_lock
//     About:
//         Wrapper function to create lock file, used for specifying what watch dog process to spawn
//    MITRE ATT&CK Technique:
//        T1140 - Deobfuscate/Decode Files or Infomration
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
void create_lock(int lock_id);


// lock_check
//     About:
//         Check if a lock is currently held on a file.
//    MITRE ATT&CK Technique:
//        T1140 - Deobfuscate/Decode Files or Infomration
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
int lock_check(char *fpath);

bool write_to_file(char *fpath, char *data);

#endif // UTILS_H_
