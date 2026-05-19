package protocols

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type JSONRPCRequest struct {
	Target       string
	TargetPrefix string
	Action       string
	Input        map[string]any
}

func ParseJSONRPCRequest(target string, body []byte) (JSONRPCRequest, error) {
	prefix, action, err := ParseJSONRPCTarget(target)
	if err != nil {
		return JSONRPCRequest{}, err
	}

	input := map[string]any{}
	if len(bytes.TrimSpace(body)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&input); err != nil {
			return JSONRPCRequest{}, fmt.Errorf("parse JSON RPC body: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			if err != nil {
				return JSONRPCRequest{}, fmt.Errorf("parse JSON RPC body: %w", err)
			}
			return JSONRPCRequest{}, fmt.Errorf("parse JSON RPC body: unexpected trailing data")
		}
	}

	return JSONRPCRequest{
		Target:       target,
		TargetPrefix: prefix,
		Action:       action,
		Input:        input,
	}, nil
}

func ParseJSONRPCTarget(target string) (string, string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("missing JSON RPC target")
	}
	index := strings.LastIndex(target, ".")
	if index <= 0 || index == len(target)-1 {
		return "", "", fmt.Errorf("invalid JSON RPC target %q", target)
	}
	return target[:index], target[index+1:], nil
}
