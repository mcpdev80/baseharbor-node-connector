package health

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// NodeMemory is observed on the execution node. Runtime-info totals alone do
// not establish available capacity and must not be substituted for this data.
type NodeMemory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapFreeBytes  uint64 `json:"swap_free_bytes"`
}

func readNodeMemory() *NodeMemory {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	memory, err := parseNodeMemory(f)
	if err != nil {
		return nil
	}
	return &memory
}

func parseNodeMemory(reader io.Reader) (NodeMemory, error) {
	values := map[string]uint64{}
	scanner := bufio.NewScanner(io.LimitReader(reader, 64<<10))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		switch key {
		case "MemTotal", "MemAvailable", "SwapTotal", "SwapFree":
			if len(fields) != 3 || fields[2] != "kB" {
				return NodeMemory{}, errors.New("invalid node memory units")
			}
			if _, seen := values[key]; seen {
				return NodeMemory{}, errors.New("duplicate node memory field")
			}
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || value > ^uint64(0)/1024 {
				return NodeMemory{}, errors.New("invalid node memory value")
			}
			values[key] = value * 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return NodeMemory{}, err
	}
	for _, key := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		if _, ok := values[key]; !ok {
			return NodeMemory{}, errors.New("incomplete node memory evidence")
		}
	}
	if values["MemTotal"] == 0 || values["MemAvailable"] > values["MemTotal"] || values["SwapFree"] > values["SwapTotal"] {
		return NodeMemory{}, errors.New("inconsistent node memory evidence")
	}
	return NodeMemory{values["MemTotal"], values["MemAvailable"], values["SwapTotal"], values["SwapFree"]}, nil
}
