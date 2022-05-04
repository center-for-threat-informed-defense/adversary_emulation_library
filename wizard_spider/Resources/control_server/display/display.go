package display

import (
	"fmt"
	"os"

	"attackevals.mitre-engenuity.org/control_server/logger"
	"attackevals.mitre-engenuity.org/control_server/sessions"
	"github.com/olekukonko/tablewriter"
)

func PrintSession(s sessions.Session) {
	fmt.Println()
	logger.Success("*** New session established ***")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"GUID", "IP Address", "Hostname", "User", "PID", "PPID"})
	output := []string{s.GUID, s.IPAddr, s.HostName, s.User, fmt.Sprint(s.PID), fmt.Sprint(s.PPID)}
	table.Append(output)
	table.Render()
	fmt.Println("Current Directory: ", s.Dir)
}

func PrintSessionList(sessionList []sessions.Session) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"GUID", "IP Address", "Hostname", "User", "CWD", "PID", "PPID"})
	for _, s := range sessionList {
		output := []string{s.GUID, s.IPAddr, s.HostName, s.User, s.Dir, fmt.Sprint(s.PID), fmt.Sprint(s.PPID)}
		table.Append(output)
	}
	table.Render()
}
