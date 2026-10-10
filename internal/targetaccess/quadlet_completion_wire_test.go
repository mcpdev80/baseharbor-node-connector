package targetaccess

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQuadletCompletionWireCannotSelectUnstagedOrMutableExecution(t *testing.T) {
	raw, err := ReadTargetAccessGoldenFixtures()
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Record string          `json:"record"`
		Wire   json.RawMessage `json:"wire"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid fixtures")
	}
	var valid string
	for _, fixture := range fixtures {
		if strings.Contains(string(fixture.Wire), "runtime.quadlet.verify-completion") {
			valid = string(fixture.Wire)
		}
	}
	if valid == "" || ValidateTargetAccessRecord("request", []byte(valid)) != nil {
		t.Fatal("missing completion positive control")
	}
	for _, bad := range []string{
		strings.Replace(valid, `"name": "workload.container"`, `"name": "../foreign.container"`, 1),
		strings.Replace(valid, `"name": "workload.container"`, `"name": "workload.network"`, 1),
		strings.Replace(valid, `"name": "workload.container"`, `"enable": true, "name": "workload.container"`, 1),
		strings.Replace(valid, `"project_directory": "bundles/.object-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"project_directory": "/tmp/foreign"`, 1),
		strings.Replace(valid, `"project_directory": "bundles/.object-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"other_directory": "bundles/.object-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 1),
	} {
		if bad == valid {
			t.Fatal("negative fixture did not change")
		}
		if ValidateTargetAccessRecord("request", []byte(bad)) == nil {
			t.Fatal("unsafe completion selector accepted")
		}
	}
}

func TestManagedActivationRequiresImmutablePublishedBundle(t *testing.T) {
	raw, err := ReadTargetAccessGoldenFixtures()
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Wire json.RawMessage `json:"wire"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid fixtures")
	}
	var valid map[string]any
	for _, fixture := range fixtures {
		var record map[string]any
		if json.Unmarshal(fixture.Wire, &record) == nil && record["request_id"] == "request-quadlet-core-managed" {
			valid = record
		}
	}
	if valid == nil {
		t.Fatal("missing Core managed fixture")
	}
	good, _ := json.Marshal(valid)
	if err := ValidateTargetAccessRecord("request", good); err != nil {
		t.Fatal(err)
	}
	payload := valid["payload"].(map[string]any)
	delete(payload, "project_directory")
	bad, _ := json.Marshal(valid)
	if ValidateTargetAccessRecord("request", bad) == nil {
		t.Fatal("unstaged managed activation accepted")
	}
}

func TestQuadletVolumeResetWireRefusesUnboundOrForcedRemoval(t *testing.T) {
	raw, err := ReadTargetAccessGoldenFixtures()
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Wire json.RawMessage `json:"wire"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid fixtures")
	}
	var record map[string]any
	for _, fixture := range fixtures {
		var candidate map[string]any
		if json.Unmarshal(fixture.Wire, &candidate) == nil && candidate["request_id"] == "request-quadlet-volume-reset" {
			record = candidate
		}
	}
	if record == nil {
		t.Fatal("missing positive reset fixture")
	}
	valid, _ := json.Marshal(record)
	if err := ValidateTargetAccessRecord("request", valid); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"host-path", "container", "force", "missing-bundle"} {
		var changed map[string]any
		_ = json.Unmarshal(valid, &changed)
		payload := changed["payload"].(map[string]any)
		switch scenario {
		case "host-path":
			payload["project_directory"] = "/tmp/foreign"
		case "container":
			payload["name"] = "owned.container"
		case "force":
			payload["force"] = true
		case "missing-bundle":
			delete(payload, "project_directory")
		}
		encoded, _ := json.Marshal(changed)
		if ValidateTargetAccessRecord("request", encoded) == nil {
			t.Fatal("unsafe reset request accepted", scenario)
		}
	}
}

func TestPublishedVolumeResetRequiresDurableMutationAdmission(t *testing.T) {
	if !RequiresAdmission(OpQuadletVolumeReset) {
		t.Fatal("destructive reset was treated as a read-only observation")
	}
}
