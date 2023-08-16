#ifndef PERSISTENCE_H_
#define PERSISTENCE_H_
#include <stdbool.h>



// nonroot_bashrc_persistence
//     About:
//         append to .bashrc for persistence
//    Result: Boolean value indicating success or failue of persistence mechanism created.
//    MITRE ATT&CK Technique
//        T154.004 Event Triggered Execution: Unix Shell Configuration Modification
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
bool nonroot_bashrc_persistence(void);

// nonroot_bashrc_persistence
//     About:
//         Create a ".Desktop" file for persistence
//    Result: Boolean value indicating success or failue of persistence mechanism created.
//    MITRE ATT&CK Technique
//        TODO - Technique: Desktop Entry (not documented in ATT&CK)
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
bool nonroot_desktop_persistence(void);

// nonroot_bashrc_persistence
//     About:
//         Copy binary to persistence locations by reading it from /proc/self/exe to destpath
//    Result: Boolean value indicating success or failue of rota being copied.
//    MITRE ATT&CK Technique: N/A
//    CTI: N/A
bool copy_rota_to_userland(char *destpath);


// nonroot_persistence
//     About:
//         Wrapper function to call persistence mechanisms
//    Result: calls non-root persistence functions
//    MITRE ATT&CK Technique: N/A
//    CTI: N/A
bool nonroot_persistence(void);

// root_persistence
//     About:
//         Leverage systemd/init rc scripts to achieve persistence when rota is executed as root
//    Result: Systemd files/init rc file created
//    MITRE ATT&CK Technique: N/A
//        T1037.004 Boot or Logon Initiaization Scripts
//    CTI:
//        https://attack.mitre.org/techniques/T1037/
bool root_persistence(void);


// monitor_proc
//     About:
//         monitor /proc/<PID> for existence of a given process.
//
//    Result: Boolean value returned indicating success or failure of data being written to a file.
//    MITRE ATT&CK Technique:
//        TODO - in new version of ATT&CK
//    CTI:
//        https://attack.mitre.org/techniques/T1037/
bool monitor_proc(int *pid);


// write_to_file
//     About:
//         Wrapper function to write data to a given file path
//
//    Result: Boolean value returned indicating success or failure of data being written to a file.
//    MITRE ATT&CK Technique: N/A
//    CTI: N/A
bool write_to_file(char *fpath, char *data);


// watchdog_process_shmget
//     About:
//         Intial watchdogthread, monitor shared memory for existence of other file. This function is started via a thread.
//    Result: A watchdog thread or dedicated watchdog process is spawned
//    MITRE ATT&CK Technique:
//        TODO - *in new version of ATT&CK?*
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
void *watchdog_process_shmget();


// watchdog_process_shmread
//     About:
//         Secondary watchdog thread, read shared memory for existence of other file
//
//    Result: A watchdog thread or dedicated watchdog process is spawned
//    MITRE ATT&CK Technique:
//        TODO - *in new version of ATT&CK?*
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
void *watchdog_process_shmread();

// watchdog_process_shmread
//     About:
//         Spawn watchdog thread depending on id passed to it
//    Result: A watchdog thread or dedicated watchdog process is spawned
//    MITRE ATT&CK Technique: N/A
//    CTI:
//        https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/
void spawn_thread_watchdog(int some_id);

// fork_exec
//     About:
//         Helper function to fork and exec a binary and wait for it to return.
//    Result: process is forked and exec'd
//    MITRE ATT&CK Technique: N/A
//    CTI: N/A
void fork_exec(char *fpath);

#endif // PERSISTENCE_H_
