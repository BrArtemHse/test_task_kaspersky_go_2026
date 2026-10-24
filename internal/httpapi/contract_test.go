package httpapi

import (
	"context"
	"strconv"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestResponsesMatchOpenAPI(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServer(t, 10000, 10000)
	for _, tc := range []struct {
		method, path, specPath, body string
		want                         int
	}{
		{"POST", "/info", "/info", `{"md5":"` + hash + `","name":"Trojan"}`, 201},
		{"GET", "/info/" + hash, "/info/{md5}", "", 200},
		{"PUT", "/info/" + hash, "/info/{md5}", `{"name":"Updated"}`, 200},
		{"POST", "/info", "/info", `{"md5":"` + hash + `","name":"Trojan"}`, 409},
		{"GET", "/info/bad", "/info/{md5}", "", 400},
		{"GET", "/healthz", "/healthz", "", 200},
	} {
		status, _, body := request(t, s, tc.method, tc.path, tc.body, testToken, "application/json")
		if status != tc.want {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, status, tc.want)
		}
		operation := doc.Paths.Find(tc.specPath).GetOperation(tc.method)
		schema := operation.Responses.Value(strconv.Itoa(status)).Value.Content.Get("application/json").Schema.Value
		if err := schema.VisitJSON(body); err != nil {
			t.Fatalf("%s %s violates response schema: %v", tc.method, tc.path, err)
		}
	}
}
