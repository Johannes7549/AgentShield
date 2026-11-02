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

func TestLoadRefusesProductionWithoutAppRole(t *testing.T) {
	_, err := Load(func(key string) string {
		if key == "AGENTSHIELD_ENV" {
			return "production"
		}
		return ""
	})
	if err == nil {
		t.Fatal("expected production to be refused")
	}
	_, err = Load(func(key string) string {
		switch key {
		case "AGENTSHIELD_ENV":
			return "production"
		case "DATABASE_URL":
			return "postgres://agentshield:agentshield@127.0.0.1:5432/agentshield"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("expected owner role production to be refused")
	}
	cfg, err := Load(func(key string) string {
		switch key {
		case "AGENTSHIELD_ENV":
			return "production"
		case "DATABASE_URL":
			return "postgres://agentshield_app:agentshield-app@127.0.0.1:5432/agentshield"
		case "REDIS_URL":
			return "redis://127.0.0.1:6379/0"
		default:
			return ""
		}
	})
	if err != nil || cfg.Environment != "production" {
		t.Fatalf("cfg = %+v err = %v", cfg, err)
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
