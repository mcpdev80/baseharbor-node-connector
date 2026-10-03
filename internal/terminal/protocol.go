package terminal

// Request is transport-neutral terminal intent.
// Authorization is performed by BaseHarbor Core before a connector session is created.
type Request struct {
	SessionID   string            `json:"session_id"`
	ResourceID  string            `json:"resource_id"`
	Rows        int               `json:"rows"`
	Cols        int               `json:"cols"`
	User        string            `json:"user,omitempty"`
	Workdir     string            `json:"workdir,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

type EventType string

const (
	Ready  EventType = "ready"
	Data   EventType = "data"
	Resize EventType = "resize"
	Exit   EventType = "exit"
	Error  EventType = "error"
)

type Event struct {
	Type      EventType `json:"type"`
	SessionID string    `json:"session_id,omitempty"`
	Data      []byte    `json:"data,omitempty"`
	Rows      int       `json:"rows,omitempty"`
	Cols      int       `json:"cols,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Message   string    `json:"message,omitempty"`
}
