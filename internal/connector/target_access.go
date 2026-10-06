package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	"github.com/mcpdev80/baseharbor-node-connector/internal/health"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/compose"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

type TargetAccess struct {
	service  *Service
	identity targetaccess.NodeIdentity
	health   *health.Collector
	streams  *streamReplayRegistry
}

func (s *Service) TargetAccess(identity targetaccess.NodeIdentity) (*TargetAccess, error) {
	if s == nil {
		return nil, fmt.Errorf("connector service is required")
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if identity.Identity != "spiffe://baseharbor/platform/connectors/"+identity.TenantID+"/"+identity.TargetID+"/"+identity.NodeID {
		return nil, targetaccess.ErrTargetAccessWire
	}
	if identity.Runtime != string(s.Runtime.Kind) {
		return nil, fmt.Errorf("node identity runtime %q does not match detected runtime %q", identity.Runtime, s.Runtime.Kind)
	}
	return &TargetAccess{
		service:  s,
		identity: identity,
		health:   health.NewCollector(s.Runtime.Kind),
		streams:  newStreamReplayRegistry(defaultStreamReplayEvents),
	}, nil
}

func (a *TargetAccess) Capabilities() targetaccess.CapabilitySet {
	return targetaccess.CapabilitySet{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		Node:            a.identity,
		Capabilities:    append([]capability.Descriptor(nil), a.service.Capabilities...),
	}
}

func (a *TargetAccess) Execute(ctx context.Context, request targetaccess.Request) targetaccess.Response {
	if err := request.Validate(time.Now().UTC()); err != nil {
		return targetaccess.FailureResponse(request, "invalid_request", "Invalid or expired typed request.", false)
	}
	if request.TargetID != a.identity.TargetID {
		return targetaccess.FailureResponse(request, "target_mismatch", "request target does not match connector target identity", false)
	}
	if !a.operationAvailable(request.Operation) {
		return targetaccess.FailureResponse(request, "capability_unavailable", "requested operation is not available on this connector", false)
	}

	requestCtx, cancel := context.WithDeadline(ctx, request.DeadlineAt)
	defer cancel()
	result, err := a.execute(requestCtx, request.Operation, request.Payload)
	if err != nil {
		return targetaccess.FailureResponse(request, "operation_failed", "The bounded runtime operation failed.", false)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return targetaccess.FailureResponse(request, "encode_result_failed", "The runtime result could not be encoded.", false)
	}
	return targetaccess.SuccessResponse(request, raw)
}

func (a *TargetAccess) operationAvailable(operation targetaccess.Operation) bool {
	name := capability.Name(operation)
	for _, descriptor := range a.service.Capabilities {
		if descriptor.Name == name {
			return descriptor.Available
		}
	}
	return false
}

func (a *TargetAccess) execute(ctx context.Context, operation targetaccess.Operation, payload json.RawMessage) (any, error) {
	switch operation {
	case targetaccess.OpRuntimeDetect:
		return a.service.Runtime, nil
	case targetaccess.OpResourceList:
		return a.service.Observation.List(ctx)
	case targetaccess.OpResourceInspect:
		var request targetaccess.ResourceRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return a.service.Observation.Inspect(ctx, request.ResourceID)
	case targetaccess.OpImageList:
		return a.service.Inventory.Images(ctx)
	case targetaccess.OpImagePull:
		var request targetaccess.ImagePullRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.PullImage(ctx, request.Reference)
	case targetaccess.OpVolumeList:
		return a.service.Inventory.Volumes(ctx)
	case targetaccess.OpVolumeEnsure:
		var request targetaccess.VolumeEnsureRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.EnsureVolume(ctx, request.Name)
	case targetaccess.OpVolumeRemove:
		var request targetaccess.VolumeRemoveRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.RemoveVolume(ctx, request.Name, request.Force)
	case targetaccess.OpNetworkList:
		return a.service.Inventory.Networks(ctx)
	case targetaccess.OpNetworkEnsure:
		var request targetaccess.NetworkEnsureRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.EnsureNetwork(ctx, request.Name, request.Driver)
	case targetaccess.OpNetworkRemove:
		var request targetaccess.NetworkRemoveRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.RemoveNetwork(ctx, request.ResourceID)
	case targetaccess.OpContainerStart:
		return nil, a.lifecycleResource(ctx, payload, a.service.Realizer.Start)
	case targetaccess.OpContainerStop:
		return nil, a.lifecycleResource(ctx, payload, a.service.Realizer.Stop)
	case targetaccess.OpContainerRestart:
		return nil, a.lifecycleResource(ctx, payload, a.service.Realizer.Restart)
	case targetaccess.OpContainerRemove:
		var request targetaccess.RemoveResourceRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Realizer.Remove(ctx, request.ResourceID, request.Force)
	case targetaccess.OpComposeApply:
		var request targetaccess.ComposeApplyRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return a.service.Compose.Apply(ctx, compose.ApplyRequest(request))
	case targetaccess.OpComposeDestroy:
		var request targetaccess.ComposeDestroyRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return a.service.Compose.Destroy(ctx, compose.DestroyRequest(request))
	case targetaccess.OpQuadletApply:
		var request targetaccess.QuadletApplyRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Quadlet.Apply(ctx, request.Name, request.Content, request.Enable)
	case targetaccess.OpQuadletRemove:
		var request targetaccess.QuadletNameRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Quadlet.Remove(ctx, request.Name)
	case targetaccess.OpQuadletEnable:
		var request targetaccess.QuadletNameRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Quadlet.Enable(ctx, request.Name)
	case targetaccess.OpQuadletDisable:
		var request targetaccess.QuadletNameRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return nil, a.service.Quadlet.Disable(ctx, request.Name)
	case targetaccess.OpLogRead:
		var request targetaccess.LogsRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return a.service.Observation.Logs(ctx, request.ResourceID, container.LogOptions{Tail: request.Tail, Since: request.Since})
	case targetaccess.OpExec:
		var request targetaccess.ExecRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return a.service.Observation.Exec(ctx, request.ResourceID, container.ExecRequest{
			Argv: request.Argv, Workdir: request.Workdir, Environment: request.Environment,
			TimeoutSeconds: request.TimeoutSeconds,
		})
	case targetaccess.OpMetrics:
		var request targetaccess.MetricsRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		resources, err := a.service.Observation.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			if resource.ID == request.ResourceID {
				return struct {
					ResourceID string `json:"resource_id"`
					CPUPercent string `json:"cpu_percent,omitempty"`
					Memory     string `json:"memory_usage,omitempty"`
					NetworkIO  string `json:"network_io,omitempty"`
				}{
					ResourceID: resource.ID, CPUPercent: resource.CPUPercent,
					Memory: resource.MemoryUsage, NetworkIO: resource.NetworkIO,
				}, nil
			}
		}
		return nil, fmt.Errorf("runtime resource %q was not found", request.ResourceID)
	case targetaccess.OpHealth:
		return a.health.Snapshot(ctx), nil
	case targetaccess.OpCapabilities:
		return a.Capabilities(), nil
	case targetaccess.OpBundleStage:
		var request targetaccess.Bundle
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		return targetaccess.StageBundle(a.service.Staging, request)
	default:
		return nil, fmt.Errorf("unsupported target-access operation %q", operation)
	}
}

func (a *TargetAccess) lifecycleResource(ctx context.Context, payload json.RawMessage, operation func(context.Context, string) error) error {
	var request targetaccess.ResourceRequest
	if err := decodePayload(payload, &request); err != nil {
		return err
	}
	return operation(ctx, request.ResourceID)
}

func decodePayload(payload json.RawMessage, target any) error {
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode target-access payload: %w", err)
	}
	return nil
}
