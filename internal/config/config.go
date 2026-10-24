// Package config loads and validates process configuration without global state.
package config

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// Config is immutable after startup.
type Config struct {
	Address string
	DBPath  string
	Token   string
	RPS     float64
	Burst   int
	TLSCert string
	TLSKey  string
}

// Load reads environment values through lookup; explicitly empty settings are invalid.
func Load(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		return fallback
	}
	c := Config{Address: get("HTTP_ADDR", "127.0.0.1:8080"), DBPath: get("DB_PATH", "data/threats.db"), Token: get("API_TOKEN", ""), TLSCert: get("TLS_CERT_FILE", ""), TLSKey: get("TLS_KEY_FILE", "")}
	if len(c.Token) < 32 || strings.IndexFunc(c.Token, unicode.IsSpace) >= 0 {
		return Config{}, fmt.Errorf("API_TOKEN must contain at least 32 bytes without whitespace")
	}
	if strings.TrimSpace(c.DBPath) == "" || c.DBPath == ":memory:" || strings.HasPrefix(c.DBPath, "file:") {
		return Config{}, fmt.Errorf("DB_PATH must be a filesystem path")
	}
	_, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return Config{}, fmt.Errorf("HTTP_ADDR must be a host:port address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("HTTP_ADDR port must be between 1 and 65535")
	}
	c.RPS, err = strconv.ParseFloat(get("RATE_LIMIT_RPS", "20"), 64)
	if err != nil || math.IsNaN(c.RPS) || math.IsInf(c.RPS, 0) || c.RPS <= 0 {
		return Config{}, fmt.Errorf("RATE_LIMIT_RPS must be a finite positive number")
	}
	c.Burst, err = strconv.Atoi(get("RATE_LIMIT_BURST", "40"))
	if err != nil || c.Burst < 1 {
		return Config{}, fmt.Errorf("RATE_LIMIT_BURST must be a positive integer")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	return c, nil
}
