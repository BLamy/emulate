package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunListIncludesRegisteredServices(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("list exited with %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, service := range []string{"github", "aws", "stripe", "clerk"} {
		if !strings.Contains(out, service) {
			t.Fatalf("list output missing %q:\n%s", service, out)
		}
	}
}

func TestRunStartRejectsInvalidPort(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"start", "--port", "70000"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("start with invalid port exited successfully")
	}
	if !strings.Contains(stderr.String(), "Invalid port: 70000") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunInitWritesStarterJSON(t *testing.T) {
	tempDir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Fatal(err)
		}
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"init", "--service", "aws"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init exited with %d, stderr: %s", code, stderr.String())
	}

	raw, err := os.ReadFile(filepath.Join(tempDir, "emulate.config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if _, ok := config["tokens"]; !ok {
		t.Fatal("starter config missing tokens")
	}
	if _, ok := config["aws"]; !ok {
		t.Fatal("starter config missing aws")
	}
	if _, ok := config["github"]; ok {
		t.Fatal("service-specific starter config included github")
	}
}
