package jsondoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const MaxBytes = 1 << 20

// Parse decodes one JSON document. Duplicate object keys and trailing data
// are rejected so later redaction and hashing cannot disagree about a value.
func Parse(raw []byte) (any, error) {
	if len(raw) > MaxBytes {
		return nil, errors.New("payload too large")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, errors.New("invalid json")
	}
	if dec.More() {
		return nil, errors.New("trailing json")
	}
	return value, nil
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := consumeValue(dec); err != nil {
		return errors.New("invalid json")
	}
	var extra any
	err := dec.Decode(&extra)
	if err == nil {
		return errors.New("trailing json")
	}
	if !errors.Is(err, io.EOF) {
		return errors.New("invalid json")
	}
	return nil
}

func consumeValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate json key")
			}
			seen[key] = struct{}{}
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("expected object end")
		}
		return nil
	case '[':
		for dec.More() {
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("expected array end")
		}
		return nil
	default:
		return errors.New("unexpected delimiter")
	}
}
