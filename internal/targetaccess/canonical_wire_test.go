package targetaccess

import (
	"encoding/json"
	"testing"
)

func TestPinnedCoreGoldenRecordsSurviveConsumerRoundTrip(t *testing.T) {
	data, err := ReadTargetAccessGoldenFixtures()
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Record string          `json:"record"`
		Wire   json.RawMessage `json:"wire"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for i, fixture := range fixtures {
		t.Run(fixture.Record+string(rune('a'+i)), func(t *testing.T) {
			if err := ValidateTargetAccessRecord(fixture.Record, fixture.Wire); err != nil {
				t.Fatal(err)
			}
			var destination any
			switch fixture.Record {
			case "hello":
				destination = &Hello{}
			case "capabilities":
				destination = &CapabilitySet{}
			case "request":
				destination = &Request{}
			case "response":
				destination = &Response{}
			case "cancel":
				destination = &Cancel{}
			case "bootstrap_authorization":
				destination = &BootstrapAuthorization{}
			case "stream_open":
				destination = &StreamOpen{}
			case "stream_event":
				destination = &StreamEvent{}
			default:
				t.Fatalf("canonical fixture has no consumer decoder: %s", fixture.Record)
			}
			if err := json.Unmarshal(fixture.Wire, destination); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(destination)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateTargetAccessRecord(fixture.Record, encoded); err != nil {
				t.Fatalf("consumer dropped or changed required wire fields: %v", err)
			}
		})
	}
}

func TestCanonicalDecodeRejectsDuplicateSelectorsAndUnknownCredentials(t *testing.T) {
	data, _ := ReadTargetAccessGoldenFixtures()
	var fixtures []struct {
		Record string          `json:"record"`
		Wire   json.RawMessage `json:"wire"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		if fixture.Record != "request" {
			continue
		}
		var request Request
		if err := decodeStrictFrame(fixture.Wire, &request); err != nil {
			t.Fatal(err)
		}
		bad := append([]byte(`{"SECRET-CREDENTIAL":"hidden",`), fixture.Wire[1:]...)
		if err := decodeStrictFrame(bad, &request); err != ErrTargetAccessWire {
			t.Fatalf("unknown credential accepted or echoed: %v", err)
		}
	}
}
