package protocols

import (
	"strings"
	"testing"
)

func TestParseJSONRPCRequestRejectsTrailingData(t *testing.T) {
	tests := []string{
		`{"Limit":10} garbage`,
		`{"Limit":10} {"Next":true}`,
	}

	for _, body := range tests {
		t.Run(body, func(t *testing.T) {
			_, err := ParseJSONRPCRequest("DynamoDB_20120810.ListTables", []byte(body))
			if err == nil {
				t.Fatal("expected trailing data error")
			}
			if !strings.Contains(err.Error(), "parse JSON RPC body") {
				t.Fatalf("error = %q, want JSON RPC parse error", err)
			}
		})
	}
}

func TestParseJSONRPCRequestAllowsTrailingWhitespace(t *testing.T) {
	parsed, err := ParseJSONRPCRequest("DynamoDB_20120810.ListTables", []byte("{\"Limit\":10}\n\t "))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Action != "ListTables" {
		t.Fatalf("action = %q, want ListTables", parsed.Action)
	}
}
