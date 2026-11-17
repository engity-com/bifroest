package evidence

type SessionTask string

const (
	SessionTaskShell     SessionTask = "shell"
	SessionTaskExec      SessionTask = "exec"
	SessionTaskSftp      SessionTask = "sftp"
	SessionTaskSubsystem SessionTask = "subsystem"
)
