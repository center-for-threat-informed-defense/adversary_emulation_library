#include <file_handler.h>

namespace file_handler {

const unsigned char kLoaderDllData[] = "DUMMY LOADER DATA";
const unsigned char kOrchestratorDllData[] = "DUMMY ORCHESTRATOR DATA";
const unsigned char kCommsDllData[] = "DUMMY COMMS LIB DATA";
const std::streamsize kLoaderDllDataLen = 18;
const std::streamsize kOrchestratorDllDataLen = 24;
const std::streamsize kCommsDllDataLen = 21;

// Based on Carbon 3.77 example config file [1]
const unsigned char kConfigFileData[] = R"(
[NAME]
object_id=
iproc = iexplore.exe,outlook.exe,msimn.exe,firefox.exe,opera.exe,chrome.exe
ex = #,netscape.exe,mozilla.exe,adobeupdater.exe,chrome.exe
 
 
[TIME]
user_winmin = 1800000
user_winmax = 3600000
sys_winmin = 3600000
sys_winmax = 3700000
task_min = 20000
task_max = 30000
checkmin = 60000
checkmax = 70000
logmin =  60000
logmax = 120000
lastconnect=111
timestop=
active_con = 900000
time2task=3600000
 
 
[CW_LOCAL]
quantity = 0
 
[CW_INET]
quantity = 3
address1 = 192.168.0.4:80:/wp-content/about/
address2 = 192.168.0.4:80:/credit_payment/url/
address3 = 192.168.0.4:80:/wp-content/gallery/
 
[TRANSPORT]
system_pipe = comnap
spstatus = yes
adaptable = no
 
 
[DHCP]
server = 135
 
 
[LOG]
logperiod = 7200
 
[WORKDATA]
run_task=
run_task_system=
)";

const std::streamsize kConfigFileDataLen = 765;

} // namespace file_handler
