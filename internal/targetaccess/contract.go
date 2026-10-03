package targetaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
)

const (
	ContractVersion = "baseharbor.target-access/v1"
	ProtocolVersion = "1"
)

type NodeIdentity struct {
	NodeID     string `json:"node_id"`
	TargetID   string `json:"target_id"`
	Runtime    string `json:"runtime"`
	Identity   string `json:"identity"`
	InstanceID string `json:"instance_id,omitempty"`
}

func (n NodeIdentity) Validate() error {
	if strings.TrimSpace(n.NodeID) == "" {
		return errors.New("node_id is required")
	}
	if strings.TrimSpace(n.TargetID) == "" {
		return errors.New("target_id is required")
	}
	if strings.TrimSpace(n.Runtime) == "" {
		return errors.New("runtime is required")
	}
	if strings.TrimSpace(n.Identity) == "" {
		return errors.New("identity is required")
	}
	return nil
}

type CapabilitySet struct {
	ContractVersion string                  `json:"contract_version"`
	ProtocolVersion string                  `json:"protocol_version"`
	Node            NodeIdentity            `json:"node"`
	Capabilities    []capability.Descriptor `json:"capabilities"`
}

func (c CapabilitySet) Validate() error {
	if c.ContractVersion != ContractVersion {
		return fmt.Errorf("unsupported target-access contract version %q", c.ContractVersion)
	}
	if c.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported target-access protocol version %q", c.ProtocolVersion)
	}
	return c.Node.Validate()
}

type Operation string

const (
	OpRuntimeDetect    Operation = "runtime.detect"
	OpResourceList     Operation = "runtime.resource.list"
	OpResourceInspect  Operation = "runtime.resource.inspect"
	OpImageList        Operation = "runtime.image.list"
	OpImagePull        Operation = "runtime.image.pull"
	OpVolumeList       Operation = "runtime.volume.list"
	OpVolumeEnsure     Operation = "runtime.volume.ensure"
	OpVolumeRemove     Operation = "runtime.volume.remove"
	OpNetworkList      Operation = "runtime.network.list"
	OpNetworkEnsure    Operation = "runtime.network.ensure"
	OpNetworkRemove    Operation = "runtime.network.remove"
	OpContainerStart   Operation = "runtime.container.start"
	OpContainerStop    Operation = "runtime.container.stop"
	OpContainerRestart Operation = "runtime.container.restart"
	OpContainerRemove  Operation = "runtime.container.remove"
	OpComposeApply     Operation = "runtime.compose.apply"
	OpComposeDestroy   Operation = "runtime.compose.destroy"
	OpQuadletApply     Operation = "runtime.quadlet.apply"
	OpQuadletRemove    Operation = "runtime.quadlet.remove"
	OpQuadletEnable    Operation = "runtime.quadlet.enable"
	OpQuadletDisable   Operation = "runtime.quadlet.disable"
	OpLogRead          Operation = "runtime.logs.read"
	OpExec             Operation = "runtime.exec"
	OpMetrics          Operation = "runtime.metrics"
	OpHealth           Operation = "connector.health"
	OpCapabilities     Operation = "connector.capabilities"
	OpBundleStage      Operation = "artifact.bundle.stage"
)

var allowedOperations = map[Operation]struct{}{
	OpRuntimeDetect: {}, OpResourceList: {}, OpResourceInspect: {},
	OpImageList: {}, OpImagePull: {}, OpVolumeList: {}, OpVolumeEnsure: {}, OpVolumeRemove: {},
	OpNetworkList: {}, OpNetworkEnsure: {}, OpNetworkRemove: {}, OpContainerStart: {}, OpContainerStop: {},
	OpContainerRestart: {}, OpContainerRemove: {}, OpComposeApply: {}, OpComposeDestroy: {},
	OpQuadletApply: {}, OpQuadletRemove: {}, OpQuadletEnable: {}, OpQuadletDisable: {},
	OpLogRead: {}, OpExec: {}, OpMetrics: {}, OpHealth: {}, OpCapabilities: {}, OpBundleStage: {},
}

func (o Operation) Validate() error {
	if _, ok := allowedOperations[o]; !ok {
		return fmt.Errorf("target-access operation %q is not allowed", o)
	}
	return nil
}

type Request struct {
	ContractVersion string          `json:"contract_version"`
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	CorrelationID   string          `json:"correlation_id,omitempty"`
	TargetID        string          `json:"target_id"`
	Operation       Operation       `json:"operation"`
	IssuedAt        time.Time       `json:"issued_at"`
	Payload         json.RawMessage `json:"payload,omitempty"`
}

func (r Request) Validate(now time.Time) error {
	if r.ContractVersion != ContractVersion {
		return fmt.Errorf("unsupported target-access contract version %q", r.ContractVersion)
	}
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported target-access protocol version %q", r.ProtocolVersion)
	}
	if strings.TrimSpace(r.RequestID) == "" {
		return errors.New("request_id is required")
	}
	if strings.TrimSpace(r.TargetID) == "" {
		return errors.New("target_id is required")
	}
	if err := r.Operation.Validate(); err != nil {
		return err
	}
	if r.IssuedAt.IsZero() {
		return errors.New("issued_at is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	const skew = 5 * time.Minute
	if r.IssuedAt.Before(now.Add(-skew)) || r.IssuedAt.After(now.Add(skew)) {
		return errors.New("issued_at is outside the accepted clock-skew window")
	}
	return nil
}

type Response struct {
	ContractVersion string          `json:"contract_version"`
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	CorrelationID   string          `json:"correlation_id,omitempty"`
	Success         bool            `json:"success"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *Error          `json:"error,omitempty"`
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

func SuccessResponse(request Request, result json.RawMessage) Response {
	return Response{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		RequestID:       request.RequestID,
		CorrelationID:   request.CorrelationID,
		Success:         true,
		Result:          append(json.RawMessage(nil), result...),
	}
}

func FailureResponse(request Request, code, message string, retryable bool) Response {
	return Response{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		RequestID:       request.RequestID,
		CorrelationID:   request.CorrelationID,
		Success:         false,
		Error:           &Error{Code: code, Message: message, Retryable: retryable},
	}
}
