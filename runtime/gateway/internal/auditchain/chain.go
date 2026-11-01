// Package auditchain hashes redacted security events into a per-organization chain.
//
// The database trigger enforces linkage. This package is the canonical hash.
// A verifier must recompute EventHash from the stored event and compare it
// with the chain row. Linkage alone does not prove the payload is unchanged
// if a database owner replaces both together; the hash makes that replacement
// detectable to a party that kept an earlier head.
package auditchain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/jsondoc"
)

const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Event struct {
	EventID         string
	OrganizationID  string
	EventType       string
	OccurredAt      time.Time
	PayloadRedacted json.RawMessage
}

type Link struct {
	PrevHash    string
	EventHash   string
	PayloadHash string
}

func Hash(prevHash string, event Event) (Link, error) {
	if !isHex64(prevHash) {
		return Link{}, errors.New("prev hash must be 64 lowercase hex characters")
	}
	if event.EventID == "" || event.OrganizationID == "" || event.EventType == "" {
		return Link{}, errors.New("event identity fields are required")
	}
	if event.OccurredAt.IsZero() {
		return Link{}, errors.New("occurred_at is required")
	}
	payload := event.PayloadRedacted
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	value, err := jsondoc.Parse(payload)
	if err != nil {
		return Link{}, errors.New("payload must be valid json")
	}
	canonicalPayload, err := Canonical(value)
	if err != nil {
		return Link{}, err
	}
	payloadSum := sha256.Sum256(canonicalPayload)
	payloadHash := hex.EncodeToString(payloadSum[:])
	header := map[string]string{
		"event_id":        event.EventID,
		"event_type":      event.EventType,
		"occurred_at":     event.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		"organization_id": event.OrganizationID,
		"payload_hash":    payloadHash,
		"prev_hash":       prevHash,
	}
	canonicalHeader, err := Canonical(header)
	if err != nil {
		return Link{}, err
	}
	eventSum := sha256.Sum256(canonicalHeader)
	return Link{
		PrevHash:    prevHash,
		PayloadHash: payloadHash,
		EventHash:   hex.EncodeToString(eventSum[:]),
	}, nil
}

// Verify recomputes the event hash. It does not consult the database head.
func Verify(prevHash string, event Event, eventHash string) error {
	link, err := Hash(prevHash, event)
	if err != nil {
		return err
	}
	if len(link.EventHash) != len(eventHash) || subtle.ConstantTimeCompare([]byte(link.EventHash), []byte(eventHash)) != 1 {
		return errors.New("audit event hash mismatch")
	}
	return nil
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Canonical encodes JSON with sorted object keys and encoding/json string
// escaping. Hashes of policy documents and audit payloads use these bytes.
func Canonical(value any) ([]byte, error) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, key := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			encodedValue, err := Canonical(typed[key])
			if err != nil {
				return nil, err
			}
			buf = append(buf, encodedKey...)
			buf = append(buf, ':')
			buf = append(buf, encodedValue...)
		}
		buf = append(buf, '}')
		return buf, nil
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, value := range typed {
			converted[key] = value
		}
		return Canonical(converted)
	case []any:
		buf := []byte{'['}
		for i, child := range typed {
			if i > 0 {
				buf = append(buf, ',')
			}
			encoded, err := Canonical(child)
			if err != nil {
				return nil, err
			}
			buf = append(buf, encoded...)
		}
		buf = append(buf, ']')
		return buf, nil
	case json.Number:
		return []byte(typed.String()), nil
	default:
		return json.Marshal(typed)
	}
}
