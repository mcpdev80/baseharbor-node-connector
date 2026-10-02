package capability

type Name string

const (
	RuntimeDetect  Name = "runtime.detect"
	ResourceList   Name = "runtime.resource.list"
	ResourceInspect Name = "runtime.resource.inspect"
	LogRead        Name = "runtime.logs.read"
	Exec           Name = "runtime.exec"
	Terminal       Name = "runtime.terminal"
	Metrics        Name = "runtime.metrics"
	Health         Name = "connector.health"
)

type Descriptor struct {
	Name      Name   `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}

func Baseline() []Descriptor {
	return []Descriptor{
		{Name: RuntimeDetect, Available: true},
		{Name: ResourceList, Available: true},
		{Name: ResourceInspect, Available: true},
		{Name: LogRead, Available: true},
		{Name: Exec, Available: true},
		{Name: Terminal, Available: false, Detail: "transport/session binding pending BaseHarbor target-access contract"},
		{Name: Metrics, Available: true},
		{Name: Health, Available: true},
	}
}
