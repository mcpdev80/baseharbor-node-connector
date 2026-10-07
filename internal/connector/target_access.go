package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	service    *Service
	identity   targetaccess.NodeIdentity
	health     *health.Collector
	streams    *streamReplayRegistry
	admissions *targetaccess.AdmissionJournal
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
	var journal *targetaccess.AdmissionJournal
	if s.TransportStateRoot != "" {
		var err error
		journal, err = targetaccess.NewAdmissionJournal(s.TransportStateRoot, identity)
		if err != nil {
			return nil, err
		}
	}
	return &TargetAccess{
		admissions: journal,
		service:    s,
		identity:   identity,
		health:     health.NewCollector(s.Runtime.Kind),
		streams:    newStreamReplayRegistry(defaultStreamReplayEvents),
	}, nil
}

func (a *TargetAccess) Capabilities() targetaccess.CapabilitySet {
	descriptors := append([]capability.Descriptor(nil), a.service.Capabilities...)
	if a.admissions == nil {
		for i := range descriptors {
			if targetaccess.RequiresAdmission(targetaccess.Operation(descriptors[i].Name)) {
				descriptors[i].Available = false
				descriptors[i].Detail = "Persistent transport admission is unavailable."
			}
		}
	}
	return targetaccess.CapabilitySet{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		Node:            a.identity,
		Capabilities:    descriptors,
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
	if targetaccess.RequiresAdmission(request.Operation) {
		err := a.admissions.Admit(requestCtx, request)
		if err != nil {
			code := "capability_unavailable"
			message := "Persistent transport admission failed."
			if errors.Is(err, targetaccess.ErrReplayConflict) {
				code = "replay_conflict"
				message = "Request identifier content conflicts with durable admission."
			}
			if errors.Is(err, targetaccess.ErrReplayAmbiguous) {
				code = "replay_ambiguous"
				message = "Request was already admitted; reconcile observed state before a new operation."
			}
			return targetaccess.FailureResponse(request, code, message, false)
		}
	}
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
	if targetaccess.RequiresAdmission(operation) && a.admissions == nil {
		return false
	}
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
		if request.Autostart != nil && request.ProjectDirectory == "" {
			return nil, errors.New("activation mode requires a published bundle")
		}
		if request.ProjectDirectory != "" {
			if request.Autostart != nil && !*request.Autostart {
				return nil, a.service.Quadlet.ApplyPublishedManaged(ctx, a.service.Staging, request.ProjectDirectory, request.Name, request.Content, request.Enable)
			}
			return nil, a.service.Quadlet.ApplyPublished(ctx, a.service.Staging, request.ProjectDirectory, request.Name, request.Content, request.Enable)
		}
		return nil, a.service.Quadlet.Apply(ctx, request.Name, request.Content, request.Enable)
	case targetaccess.OpQuadletCompletion:
		var request targetaccess.QuadletCompletionRequest
		if err := decodePayload(payload, &request); err != nil {
			return nil, err
		}
		if a.service.Quadlet == nil || a.service.Staging == nil {
			return nil, errors.New("published completion verification is unavailable")
		}
		if err := a.service.Quadlet.VerifyPublishedCompletion(ctx, a.service.Staging, request.ProjectDirectory, request.Name, request.Content); err != nil {
			return nil, err
		}
		digest := sha256.Sum256([]byte(request.Content))
		return targetaccess.QuadletCompletionResult{Name: request.Name, ProjectDirectory: request.ProjectDirectory,
			ContentSHA256: hex.EncodeToString(digest[:]), Completed: true}, nil
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
		return targetaccess.StageBundle(ctx, a.service.Staging, request)
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

func (a *TargetAccess) Close() error {
	if a == nil || a.admissions == nil {
		return nil
	}
	return a.admissions.Close()
}
