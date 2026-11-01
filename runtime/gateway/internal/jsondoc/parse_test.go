package jsondoc

import (
	"strings"
	"testing"
)

func TestParseRejectsDuplicatesAndTrailingData(t *testing.T) {
	if _, err := Parse([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("accepted a duplicate key")
	}
	if _, err := Parse([]byte(`{"outer":{"b":1,"b":2}}`)); err == nil {
		t.Fatal("accepted a nested duplicate key")
	}
	if _, err := Parse([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Fatal("accepted trailing json")
	}
	value, err := Parse([]byte(`{"a":1,"b":[true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		t.Fatalf("value = %#v", value)
	}
}

func TestParseDoesNotEchoInput(t *testing.T) {
	secret := "super-secret-value"
	_, err := Parse([]byte(`{"password":"` + secret))
	if err == nil {
		t.Fatal("expected invalid json")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked input: %v", err)
	}
}

func TestParseRejectsOversizedPayload(t *testing.T) {
	raw := make([]byte, MaxBytes+1)
	for i := range raw {
		raw[i] = ' '
	}
	if _, err := Parse(raw); err == nil {
		t.Fatal("accepted an oversized payload")
	}
}
