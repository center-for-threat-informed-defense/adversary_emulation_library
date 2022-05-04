package execute

import (
	"os/exec"
)

func ExecShellCommand(cmd string) ([]byte, error) {
	cmdHandle := exec.Command("cmd.exe", "/k", cmd)
	output, err := cmdHandle.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return output, err
}

// invoke this via a Go routine
func ExecBackgroundCommand(cmd string) {
	cmdHandle := exec.Command("cmd.exe", "/k", cmd)
	cmdHandle.CombinedOutput()
}

func ParseExecCmd(task string) string {
	// strip 'exec-cmd '
	parsedTask := task[9:]
	return parsedTask
}
