package config

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		valid            bool
	}{
		{"defaults", "", "", true},
		{"missing token", "API_TOKEN", "", false},
		{"short token", "API_TOKEN", "short", false},
		{"empty path", "DB_PATH", "", false},
		{"zero rate", "RATE_LIMIT_RPS", "0", false},
		{"nan rate", "RATE_LIMIT_RPS", "NaN", false},
		{"infinite rate", "RATE_LIMIT_RPS", "+Inf", false},
		{"invalid burst", "RATE_LIMIT_BURST", "abc", false},
		{"zero burst", "RATE_LIMIT_BURST", "0", false},
		{"half TLS", "TLS_CERT_FILE", "cert.pem", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{"API_TOKEN": strings.Repeat("a", 32)}
			if tc.key != "" {
				values[tc.key] = tc.value
			}
			cfg, err := Load(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
			if (err == nil) != tc.valid {
				t.Fatalf("cfg=%+v err=%v", cfg, err)
			}
			if tc.valid && (cfg.Address != "127.0.0.1:8080" || cfg.DBPath != "data/threats.db") {
				t.Fatalf("defaults: %+v", cfg)
			}
		})
	}
}
