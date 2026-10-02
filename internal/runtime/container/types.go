package container

type Resource struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Image          string   `json:"image"`
	Status         string   `json:"status"`
	State          string   `json:"state"`
	Ports          []string `json:"ports,omitempty"`
	Created        string   `json:"created,omitempty"`
	ComposeProject string   `json:"compose_project,omitempty"`
	ComposeService string   `json:"compose_service,omitempty"`
	QuadletUnit    string   `json:"quadlet_unit,omitempty"`
	CPUPercent     string   `json:"cpu_percent,omitempty"`
	MemoryUsage    string   `json:"memory_usage,omitempty"`
	NetworkIO      string   `json:"network_io,omitempty"`
}

type LogOptions struct {
	Tail  int
	Since string
}

type ExecRequest struct {
	Argv           []string          `json:"argv"`
	Workdir        string            `json:"workdir,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type ExecResult struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code"`
}
