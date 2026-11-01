package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONRedactsSensitiveKeysOnly(t *testing.T) {
	input := []byte(`{
	  "password": "hunter2",
	  "profile": {"api_key": "abc", "name": "ada", "note": "password reset instructions"},
	  "items": [{"access-key": "k"}, {"count": 2}]
	}`)
	output, err := JSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "hunter2") || strings.Contains(string(output), "abc") || strings.Contains(string(output), `"k"`) {
		t.Fatalf("secret survived: %s", output)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["password"] != Replacement {
		t.Fatalf("password = %#v", decoded["password"])
	}
	profile := decoded["profile"].(map[string]any)
	if profile["name"] != "ada" {
		t.Fatalf("name = %#v", profile["name"])
	}
	if profile["note"] != "password reset instructions" {
		t.Fatalf("note was rewritten: %#v", profile["note"])
	}
}

func TestJSONRejectsInvalidInputWithoutEcho(t *testing.T) {
	secret := "super-secret-value"
	_, err := JSON([]byte(`{"token":"` + secret))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked input: %v", err)
	}
}
