package execute_test

import (
	"testing"

	"attackevals.mitre-engenuity.org/exaramel-windows/execute"
)

func TestExecShellCommand(t *testing.T) {
	cmd := "whoami"
	_, err := execute.ExecShellCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}

	cmd = "powershell.exe -c Get-Process"
	_, err = execute.ExecShellCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
}
