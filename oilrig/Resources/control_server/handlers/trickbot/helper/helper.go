package helper

import (
	"strings"
	"strconv"
	"encoding/json"
	"attackevals.mitre-engenuity.org/control_server/logger"
)

type RegistrationData struct {
    IPAddr string
    User string
    HostName string
    Dir string
    PID int
    PPID int
    GUID string
}
 //camp1/dragon_W602931718.0iUYavZhCaJrfKXUc9DFZxooo4t5aQZC/0/windows/1234/0.0.0.0/9CD76C0730B980B292D7A835FE5F9D21525E459BF2C317579A75F33857175EAB/cwd/pid/ppid/random_string"
func GetRegistrationInfo(uri string) ([]byte){
	s := strings.Split(uri, "/")
    uid, externalip, cwd, pid, ppid, guid  := s[2], s[6], s[8], s[9], s[10], s[11]
	uidSplit := strings.Split(uid, "_")
	username := uidSplit[0]
	hostsplit := strings.Split(uidSplit[1], ".")
	hostname := hostsplit[0]
	pidint,err := strconv.Atoi(pid)
	if err != nil {
		logger.Error(err)
	}
	ppidint,err := strconv.Atoi(ppid)
	if err != nil {
		logger.Error(err)
	}
	registrationData,err := json.Marshal(RegistrationData{externalip, username, hostname, cwd, pidint, ppidint, guid})
	if err != nil {
		logger.Error(err)
	}
	return registrationData
}

func GetDownloadTaskFilename(uri string) (string){
	s := strings.Split(uri, "/")
	filename := s[4]
	return filename
}