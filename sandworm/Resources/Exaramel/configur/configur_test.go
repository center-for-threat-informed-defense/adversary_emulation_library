package configur_test

import (
	"crypto/rc4"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"attackevals.mitre-engenuity.org/exaramel/configur"
	"github.com/google/go-cmp/cmp"
)

// Testing creation and deletion of UNIX Domain socket.
func TestCreateSocket(t *testing.T) {

	// Removing all sockets with the specific socket name before continuing test.
	const SockAddr = "/tmp/.applocktx"
	if err := os.RemoveAll(SockAddr); err != nil {
		t.Errorf("Failed to remove existing socket: %s", err)
	}

	sock, err := configur.CreateSocket()
	if err != nil {
		t.Errorf("Failed to create socket.")
	}

	// This next line should fail, as there should already be an existing socket.
	sock2, err := net.Listen("unix", SockAddr)
	if err == nil {
		sock2.Close()
		t.Errorf("Test made new socket, function failed to create socket.")
	}

	sock.Close()
}

// Testing handling of signals.
// A new instance of the test is started to test crashing.
// The initial instance checks that the second exits as intended.
func TestSignalHandler(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		sock, err := configur.CreateSocket()
		if err != nil {
			t.Error(err)
		}
		sigs := configur.SetupSignalHandler(sock)
		sigs <- syscall.SIGTERM
		time.Sleep(time.Second * 3)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSignalHandler")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

// Testing that the default configuration is written to disk correctly with encryption.
func TestWriteConfig(t *testing.T) {
	testServerAddress := "http://localhost/api/v1"
	configur.SetDefaultServerAddress(testServerAddress)
	err := configur.WriteConfig()
	if err != nil {
		t.Error(err)
	}

	var config configur.Config
	testConfig := configur.Config{
		Hosts:    []string{testServerAddress},
		Proxy:    "",
		Version:  "1",
		Next:     20,
		Datetime: "",
		Timeout:  30,
		Def:      20,
	}

	configFileName := "configtx.json"
	configFile, err := os.Open(configFileName)
	if err != nil {
		t.Error(err)
	}
	defer configFile.Close()
	configEnc, err := ioutil.ReadAll(configFile)
	if err != nil {
		t.Error(err)
	}

	cipher, err := rc4.NewCipher(configur.ConfigKey)
	if err != nil {
		t.Error(err)
	}
	configDec := make([]byte, len(configEnc))
	cipher.XORKeyStream(configDec, configEnc)

	json.Unmarshal(configDec, &config)

	if !cmp.Equal(config, testConfig) {
		t.Error(fmt.Errorf("Written config did not match Expected config.\nWritten Config: %+v\nExpected Config: %+v", config, testConfig))
	}

	err = os.Remove(configFileName)
	if err != nil {
		t.Error(err)
	}
	configur.ExaramelConfig = configur.Config{}
}

// Testing that a written configuration is read correctly.
func TestReadConfig(t *testing.T) {
	testServerAddress := "http://localhost1/api/v1"
	configur.SetDefaultServerAddress(testServerAddress)
	err := configur.WriteConfig()
	if err != nil {
		t.Error(err)
	}
	configur.ExaramelConfig.Hosts = []string{}
	if len(configur.ExaramelConfig.Hosts) != 0 {
		t.Error(errors.New("Config hosts not cleared"))
	}

	err = configur.ReadConfig()
	if err != nil {
		t.Error(err)
	}
	if configur.ExaramelConfig.Hosts[0] != testServerAddress {
		t.Error(fmt.Errorf("Config address did not match %v: %v", testServerAddress, configur.ExaramelConfig.Hosts[0]))
	}

	err = os.Remove("configtx.json")
	if err != nil {
		t.Error(err)
	}
	configur.ExaramelConfig = configur.Config{}
}

// Testing that crontab persistence is done correctly. Only run when testing in a low priv context.
func testCrontabPersistence(t *testing.T) {
	cronFileName := "user.cron"
	userCronContents, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Error(err)
		}
	}
	err = ioutil.WriteFile(cronFileName, userCronContents, 0644)
	if err != nil {
		t.Error(err)
	}
	err = configur.SetupCrontabPersistence()
	if err != nil {
		t.Error(err)
	}

	newCronContents, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		t.Error(err)
	}

	mydir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	exeName, err := os.Executable()
	if err != nil {
		fmt.Println(err)
	}

	cronMinuteString := fmt.Sprintf("1 * * * * cd %s && %s\n", mydir, exeName)
	cronStartupString := fmt.Sprintf("@reboot cd %s && %s\n", mydir, exeName)

	if !strings.Contains(string(newCronContents[:]), cronMinuteString) {
		t.Errorf("cronMinuteString is not in new Crontab\nCronMinuteString: %v\nNew Crontab: %v", cronMinuteString, string(newCronContents[:]))
	}
	if !strings.Contains(string(newCronContents[:]), cronStartupString) {
		t.Errorf("cronMinuteString is not in new Crontab\nCronMinuteString: %v\nNew Crontab: %v", cronStartupString, string(newCronContents[:]))
	}

	cronFile, err := os.Stat(cronFileName)
	if err != nil {
		t.Error(err)
	}
	if cronFile.Size() == 0 {
		if err = exec.Command("crontab", "-r").Run(); err != nil {
			t.Error(err)
		}
		if err = os.Remove(cronFileName); err != nil {
			t.Error(err)
		}
	} else {
		if err = exec.Command("crontab", cronFileName).Run(); err != nil {
			t.Error(err)
		}
	}
}

// Testing that systemd persistence is done correctly. Only run in a high priv context.
func testSystemdPersistence(t *testing.T) {
	serviceFilePath := "/etc/systemd/system/syslogd.service"
	if _, err := os.Stat(serviceFilePath); err == nil {
		t.Errorf("service file already exists, rerun test after removing")
	}
	err := configur.SetupSystemdPersistence()
	if err != nil {
		t.Error(err)
	}

	progPath, err := os.Executable()
	if err != nil {
		t.Error(err)
	}
	serviceExecString := "ExecStart=" + progPath
	serviceFileContents, err := ioutil.ReadFile(serviceFilePath)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(serviceFileContents[:]), serviceExecString) {
		t.Errorf("service file does not contain: %v\nService File Contents: %v", serviceExecString, serviceFileContents)
	}

	err = exec.Command("systemctl", "is-enabled", "syslogd.service").Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Errorf("service is not enabled: %v", exitErr)
		} else {
			t.Error(err)
		}
	}

	err = configur.DeleteSystemdPersistence()
	if err != nil {
		t.Error(err)
	}
	err = exec.Command("systemctl", "is-enabled", "syslogd.service").Run()
	if err == nil {
		t.Error("Exit code should be non-zero!")
	}
	if _, err := os.Stat(serviceFilePath); err == nil {
		t.Errorf("service file should not exist anymore!")
	}
}

// Runs either crontab persistence test or systemd persistence depending on privilege level.
func TestPersistence(t *testing.T) {
	if os.Geteuid() == 0 {
		testSystemdPersistence(t)
	} else {
		testCrontabPersistence(t)
	}
}
