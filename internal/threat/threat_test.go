package threat

import (
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	underflow := time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
	for _, tc := range []struct {
		name  string
		md5   string
		input Input
		valid bool
	}{
		{"minimal", "D41D8CD98F00B204E9800998ECF8427E", Input{Name: "  Trojan  "}, true},
		{"full", "d41d8cd98f00b204e9800998ecf8427e", Input{Name: "Троян", Category: "trojan", Severity: "high", FirstSeen: &past}, true},
		{"short hash", "deadbeef", Input{Name: "x"}, false},
		{"non hex", strings.Repeat("z", 32), Input{Name: "x"}, false},
		{"blank name", strings.Repeat("a", 32), Input{Name: " \t "}, false},
		{"nul name", strings.Repeat("a", 32), Input{Name: "\x00"}, false},
		{"nul description", strings.Repeat("a", 32), Input{Name: "x", Description: "\x00"}, false},
		{"long unicode name", strings.Repeat("a", 32), Input{Name: strings.Repeat("я", 256)}, false},
		{"unicode limit", strings.Repeat("a", 32), Input{Name: strings.Repeat("я", 255)}, true},
		{"long description", strings.Repeat("a", 32), Input{Name: "x", Description: strings.Repeat("x", 4097)}, false},
		{"severity", strings.Repeat("a", 32), Input{Name: "x", Severity: "urgent"}, false},
		{"category", strings.Repeat("a", 32), Input{Name: "x", Category: "bad"}, false},
		{"future", strings.Repeat("a", 32), Input{Name: "x", FirstSeen: &future}, false},
		{"UTC year underflow", strings.Repeat("a", 32), Input{Name: "x", FirstSeen: &underflow}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate(tc.md5, tc.input, now)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, got %v", tc.valid, err)
			}
			if tc.valid && (got.MD5 != strings.ToLower(tc.md5) || got.Name != strings.TrimSpace(tc.input.Name)) {
				t.Fatalf("normalization: %+v", got)
			}
			if tc.valid && tc.input.Severity == "" && (got.Severity != "unknown" || got.Category != "unknown") {
				t.Fatalf("defaults: %+v", got)
			}
		})
	}
}

func FuzzNormalizeMD5(f *testing.F) {
	f.Add("D41D8CD98F00B204E9800998ECF8427E")
	f.Add("invalid")
	f.Fuzz(func(t *testing.T, value string) {
		got, err := NormalizeMD5(value)
		valid := len(value) == 32
		for _, c := range []byte(value) {
			valid = valid && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		}
		if (err == nil) != valid {
			t.Fatalf("incorrect acceptance for %q", value)
		}
		if err == nil && got != strings.ToLower(value) {
			t.Fatalf("normalization %q", got)
		}
	})
}
