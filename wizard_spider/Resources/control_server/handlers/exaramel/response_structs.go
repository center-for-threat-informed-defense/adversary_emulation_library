package exaramel

type RespAuth struct {
	Auth struct {
		GUID       string `json:"guid"`
		AuthResult int    `json:"auth_result"`
	} `json:"response"`
}

type RespError struct {
	Error struct {
		Code    uint32 `json:"error_code"`
		Message string `json:"error_msg"`
	} `json:"response"`
}

type Tasks struct {
	Response []TaskResponse `json:"response"`
}

type TaskResponse struct {
	// Task identification
	ID uint32 `json:"id"`
	// Task type, e.g. "OS.ShellExecute" or "IO.ReadFile"
	Method string `json:"metod"`
	// Optional argument needed for some tasks
	Arguments string `json:"arguments"`
	// Not used
	Attachment int `json:"attachment"`
	// Only for "OS.ShellExecute" task. If the field is non zero, the shell process
	// will be run in the background.
	AnswerWait int `json:"answer_wait"`
	// No real impact in task processing
	DoAsync int `json:"answer_async"`
	// If the field is non zero, the report will be sent as soon as the task ends
	AnswerImmediately int `json:"answer_immediately"`
	// Max task duration. Once it is reached the task
	// is left in the background and a report is produced.
	WaitOutputTime int `json:"wait_output_time"`
}

type Reports struct {
	Response struct {
		ID        string `json:"guid"`
		CommandID uint32 `json:"id"`
		Status    int    `json:"status"`
	} `json:"response"`
}
