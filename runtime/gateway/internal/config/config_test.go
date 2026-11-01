package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != DefaultAddr {
		t.Fatalf("addr = %s", cfg.Addr)
	}
	if cfg.Environment != "development" {
		t.Fatalf("environment = %s", cfg.Environment)
	}
	if cfg.MaxBodyBytes != 1<<20 {
		t.Fatalf("max body = %d", cfg.MaxBodyBytes)
	}
}

func TestLoadRefusesProduction(t *testing.T) {
	_, err := Load(func(key string) string {
		if key == "AGENTSHIELD_ENV" {
			return "production"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected production to be refused")
	}
}

func TestLoadRejectsOversizedBodyLimit(t *testing.T) {
	_, err := Load(func(key string) string {
		if key == "GATEWAY_MAX_BODY_BYTES" {
			return "10485761"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected body limit to be rejected")
	}
}

func TestLoadRejectsBadAddress(t *testing.T) {
	_, err := Load(func(key string) string {
		if key == "GATEWAY_HTTP_ADDR" {
			return "not-an-address"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected address to be rejected")
	}
}
