package targetaccess

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
)

const TargetAccessMaxFrameBytes = 4 << 20
const TargetAccessMaxStreamDataBytes = 16 << 10

var ErrTargetAccessWire = errors.New("invalid or unsupported Target Access wire record")

//go:embed canonical/*.json
var targetAccessFixtures embed.FS

var wireRecords = map[string]bool{
	"hello": true, "capabilities": true, "request": true, "response": true, "cancel": true,
	"enrollment_request": true, "enrollment_response": true, "bootstrap_authorization": true,
	"stream_open": true, "stream_event": true,
}

var wireCache struct {
	sync.Once
	schemas map[string]*jsonschema.Resolved
	err     error
}

// ReadTargetAccessGoldenFixtures returns packaged, synthetic protocol examples.
// Fixtures are structural examples, not certificates or runtime evidence.
func ReadTargetAccessGoldenFixtures() ([]byte, error) {
	return targetAccessFixtures.ReadFile("canonical/wire.golden.json")
}

// ValidateTargetAccessRecord resolves the canonical packaged schema offline.
// It rejects ambiguous JSON, unknown properties and unbounded transport records.
// Session authentication, request deadlines and ownership remain Core decisions.
func ValidateTargetAccessRecord(record string, data []byte) error {
	if !wireRecords[record] || len(data) == 0 || len(data) > TargetAccessMaxFrameBytes || !utf8.Valid(data) {
		return ErrTargetAccessWire
	}
	wireCache.Do(resolveWireSchemas)
	if wireCache.err != nil {
		return ErrTargetAccessWire
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	value, err := strictWireValue(decoder, 0)
	if err != nil {
		return ErrTargetAccessWire
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrTargetAccessWire
	}
	if err := wireCache.schemas[record].Validate(value); err != nil {
		return ErrTargetAccessWire
	}
	object, ok := value.(map[string]any)
	if !ok {
		return ErrTargetAccessWire
	}
	for _, field := range []string{"issued_at", "deadline_at", "observed_at", "not_after", "expires_at"} {
		if raw, present := object[field]; present {
			text, ok := raw.(string)
			if !ok {
				return ErrTargetAccessWire
			}
			if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
				return ErrTargetAccessWire
			}
		}
	}
	if record == "bootstrap_authorization" || record == "enrollment_request" || record == "enrollment_response" {
		for _, field := range []string{"token", "nonce"} {
			if raw, present := object[field]; present {
				text := raw.(string)
				decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
				if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != text {
					return ErrTargetAccessWire
				}
			}
		}
	}
	if record == "request" && object["operation"] == "runtime.exec" {
		if !boundedWireArgv(object["payload"].(map[string]any)["argv"].([]any)) {
			return ErrTargetAccessWire
		}
	}
	if record == "stream_open" && object["kind"] == "terminal" {
		if !boundedWireArgv(object["terminal"].(map[string]any)["argv"].([]any)) {
			return ErrTargetAccessWire
		}
	}
	if record == "request" && object["operation"] == "artifact.bundle.stage" {
		for _, raw := range object["payload"].(map[string]any)["files"].([]any) {
			file := raw.(map[string]any)
			encoded := file["data"].(string)
			data, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(data) != encoded {
				return ErrTargetAccessWire
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != file["sha256"] {
				return ErrTargetAccessWire
			}
		}
	}
	if record == "capabilities" {
		seen := map[string]bool{}
		for _, raw := range object["capabilities"].([]any) {
			name := raw.(map[string]any)["name"].(string)
			if seen[name] {
				return ErrTargetAccessWire
			}
			seen[name] = true
		}
	}
	if record == "stream_event" && object["type"] == "data" {
		encoded := object["data"].(string)
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) == 0 || len(decoded) > TargetAccessMaxStreamDataBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return ErrTargetAccessWire
		}
	}
	return nil
}

func resolveWireSchemas() {
	wireCache.schemas = map[string]*jsonschema.Resolved{}
	raw, err := targetAccessFixtures.ReadFile("canonical/wire.schema.json")
	if err != nil {
		wireCache.err = err
		return
	}
	for record := range wireRecords {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			wireCache.err = err
			return
		}
		document["$ref"] = "#/$defs/" + record
		selected, err := json.Marshal(document)
		if err != nil {
			wireCache.err = err
			return
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(selected, &schema); err != nil {
			wireCache.err = err
			return
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			wireCache.err = err
			return
		}
		wireCache.schemas[record] = resolved
	}
}

func strictWireValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrTargetAccessWire
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, ErrTargetAccessWire
			}
			if _, exists := object[name]; exists {
				return nil, ErrTargetAccessWire
			}
			value, err := strictWireValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, ErrTargetAccessWire
		}
		return object, nil
	case '[':
		values := []any{}
		for decoder.More() {
			value, err := strictWireValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, ErrTargetAccessWire
		}
		return values, nil
	default:
		return nil, ErrTargetAccessWire
	}
}

func boundedWireArgv(args []any) bool {
	if len(args) == 0 || args[0].(string) == "" {
		return false
	}
	size := 0
	for _, arg := range args {
		size += len(arg.(string)) + 1
	}
	return size <= 16<<10
}
