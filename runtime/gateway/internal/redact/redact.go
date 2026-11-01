// Package redact removes credential-shaped JSON values before they are logged
// or stored. Invalid JSON returns an error and must not be logged raw.
package redact

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/agentshield/agentshield/runtime/gateway/internal/jsondoc"
)

const Replacement = "[REDACTED]"

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|credential|authorization|api[_-]?key|private[_-]?key|access[_-]?key)`)

// JSON returns a compact JSON document with sensitive keys replaced.
// Object key order is normalized by encoding/json. The result is for logs
// and audit payloads, not for approval binding. Approval binds the raw body hash.
func JSON(input []byte) ([]byte, error) {
	value, err := jsondoc.Parse(input)
	if err != nil {
		return nil, errors.New("invalid json")
	}
	encoded, err := json.Marshal(redactValue(value))
	if err != nil {
		return nil, errors.New("invalid json")
	}
	return encoded, nil
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if sensitiveKey.MatchString(key) {
				out[key] = Replacement
				continue
			}
			out[key] = redactValue(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = redactValue(child)
		}
		return out
	default:
		return value
	}
}
