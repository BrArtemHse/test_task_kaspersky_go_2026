package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"
)

const maxBodyBytes = 16 * 1024

type inputError struct {
	status  int
	details string
}

func (e *inputError) Error() string { return e.details }

// decodeObject rejects ambiguity before unmarshalling into a generated request model.
// Fields must match exact JSON tags; duplicates and nulls are never accepted.
func decodeObject(w http.ResponseWriter, r *http.Request, dst any) error {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) || r.Header.Get("Content-Encoding") != "" {
		return &inputError{http.StatusUnsupportedMediaType, "use application/json with UTF-8 and no Content-Encoding"}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &inputError{http.StatusRequestEntityTooLarge, "request body exceeds 16384 bytes"}
		}
		return &inputError{http.StatusBadRequest, "cannot read request body"}
	}
	bad := &inputError{http.StatusBadRequest, "body must be one valid JSON object with known, unique, non-null fields"}
	if !utf8.Valid(body) {
		return bad
	}
	allowed := make(map[string]bool)
	typ := reflect.TypeOf(dst).Elem()
	for i := range typ.NumField() {
		allowed[strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return bad
	}
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return bad
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return bad
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad
		}
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return bad
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return bad
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return bad
	}
	return nil
}
