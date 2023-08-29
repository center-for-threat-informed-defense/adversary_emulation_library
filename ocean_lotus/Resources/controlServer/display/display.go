package display

import (
	"fmt"
	"bytes"

	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"github.com/olekukonko/tablewriter"
)

func PrintSession(s sessions.Session) {
	fmt.Println()
	tableBuffer := new(bytes.Buffer)
	table := tablewriter.NewWriter(tableBuffer)
	table.SetHeader([]string{"GUID", "IP Address", "Hostname", "User", "PID", "PPID"})
	output := []string{s.GUID, s.IPAddr, s.HostName, s.User, fmt.Sprint(s.PID), fmt.Sprint(s.PPID)}
	table.Append(output)
	table.Render()
	logger.Success(fmt.Sprintf("*** New session established: %s ***\n%s", s.GUID, tableBuffer.String()))
	logger.Info(fmt.Sprintf("Current Directory: %s", s.Dir))
}

func PrintSessionList(sessionList []sessions.Session) {
	tableBuffer := new(bytes.Buffer)
	table := tablewriter.NewWriter(tableBuffer)
	table.SetHeader([]string{"GUID", "IP Address", "Hostname", "User", "CWD", "PID", "PPID"})
	for _, s := range sessionList {
		output := []string{s.GUID, s.IPAddr, s.HostName, s.User, s.Dir, fmt.Sprint(s.PID), fmt.Sprint(s.PPID)}
		table.Append(output)
	}
	table.Render()
	logger.Info("*** Sessions ***\n" + tableBuffer.String())
}
