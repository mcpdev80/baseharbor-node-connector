package health

import "time"

type Snapshot struct {
	ObservedAt        time.Time   `json:"observed_at"`
	Runtime           string      `json:"runtime"`
	RuntimeVersion    string      `json:"runtime_version,omitempty"`
	OperatingSystem   string      `json:"operating_system,omitempty"`
	Architecture      string      `json:"architecture,omitempty"`
	CPUs              int         `json:"cpus,omitempty"`
	MemoryTotalBytes  uint64      `json:"memory_total_bytes,omitempty"`
	NodeMemory        *NodeMemory `json:"node_memory,omitempty"`
	ContainersTotal   int         `json:"containers_total,omitempty"`
	ContainersRunning int         `json:"containers_running,omitempty"`
	ImagesTotal       int         `json:"images_total,omitempty"`
}
