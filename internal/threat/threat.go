// Package threat defines threat data and transport-independent validation.
package threat

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrNotFound means no record exists for the requested MD5.
var ErrNotFound = errors.New("threat not found")

// ErrConflict means a record with the same normalized MD5 already exists.
var ErrConflict = errors.New("threat already exists")

// Input contains the complete replacement of client-editable threat attributes.
type Input struct {
	Name        string
	Description string
	Category    string
	Severity    string
	FirstSeen   *time.Time
}

// Threat is a normalized record; timestamps are assigned by persistence.
type Threat struct {
	MD5         string
	Name        string
	Description string
	Category    string
	Severity    string
	FirstSeen   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NormalizeMD5 validates and canonicalizes a file identifier.
func NormalizeMD5(value string) (string, error) {
	if len(value) != 32 {
		return "", errors.New("md5 must contain exactly 32 hexadecimal characters")
	}
	for _, c := range []byte(value) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", errors.New("md5 must contain exactly 32 hexadecimal characters")
		}
	}
	return strings.ToLower(value), nil
}

// Validate returns a normalized candidate without mutating storage.
func Validate(md5 string, input Input, now time.Time) (Threat, error) {
	key, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if strings.ContainsRune(input.Name, 0) || strings.ContainsRune(input.Description, 0) {
		return Threat{}, errors.New("name and description must not contain NUL characters")
	}
	if !utf8.ValidString(input.Name) || utf8.RuneCountInString(input.Name) < 1 || utf8.RuneCountInString(input.Name) > 255 {
		return Threat{}, errors.New("name must contain 1 to 255 Unicode characters after trimming")
	}
	if !utf8.ValidString(input.Description) || utf8.RuneCountInString(input.Description) > 4096 {
		return Threat{}, errors.New("description must contain at most 4096 Unicode characters")
	}
	if input.Category == "" {
		input.Category = "unknown"
	}
	switch input.Category {
	case "unknown", "virus", "trojan", "ransomware", "spyware", "worm", "adware", "other":
	default:
		return Threat{}, errors.New("category is not a supported value")
	}
	if input.Severity == "" {
		input.Severity = "unknown"
	}
	switch input.Severity {
	case "unknown", "low", "medium", "high", "critical":
	default:
		return Threat{}, errors.New("severity is not a supported value")
	}
	var firstSeen *time.Time
	if input.FirstSeen != nil {
		if input.FirstSeen.After(now) {
			return Threat{}, errors.New("first_seen must not be in the future")
		}
		value := input.FirstSeen.UTC()
		if value.Year() < 0 || value.Year() > 9999 {
			return Threat{}, errors.New("first_seen must remain within RFC3339 year range after conversion to UTC")
		}
		firstSeen = &value
	}
	return Threat{MD5: key, Name: input.Name, Description: input.Description, Category: input.Category, Severity: input.Severity, FirstSeen: firstSeen}, nil
}
