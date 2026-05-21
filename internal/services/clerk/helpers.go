package clerk

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func clerkID(prefix string) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return prefix + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return prefix + hex.EncodeToString(raw)[:24]
}

func clerkToken(prefix string) string {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return prefix + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}

func nowUnix() int64 {
	return time.Now().Unix()
}

func firstRecord(records []corestore.Record) corestore.Record {
	if len(records) == 0 {
		return nil
	}
	return records[0]
}

func stringField(record corestore.Record, field string) string {
	if record == nil {
		return ""
	}
	return stringValue(record[field])
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func intField(record corestore.Record, field string) int {
	if record == nil {
		return 0
	}
	return intValue(record[field])
}

func intValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}

func int64Field(record corestore.Record, field string) int64 {
	if record == nil {
		return 0
	}
	return int64Value(record[field])
}

func int64Value(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

func boolField(record corestore.Record, field string) bool {
	if record == nil {
		return false
	}
	return boolValue(record[field])
}

func boolValue(value any) bool {
	v, _ := value.(bool)
	return v
}

func mapValue(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if m, ok := value.(map[string]any); ok {
		out := make(map[string]any, len(m))
		for key, item := range m {
			out[key] = item
		}
		return out
	}
	return map[string]any{}
}

func stringSliceValue(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func readJSONBody(r *http.Request) map[string]any {
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil || body == nil {
		return map[string]any{}
	}
	return body
}

func parseTokenBody(r *http.Request) map[string]string {
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	if len(raw) == 0 {
		return map[string]string{}
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return map[string]string{}
		}
		out := map[string]string{}
		for key, value := range body {
			if text, ok := value.(string); ok {
				out[key] = text
			}
		}
		return out
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for key, list := range values {
		if len(list) > 0 {
			out[key] = list[len(list)-1]
		}
	}
	return out
}

func applyBasicCredentials(r *http.Request, clientID *string, clientSecret *string) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Basic ") {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, "Basic ")))
	if err != nil {
		return
	}
	left, right, ok := strings.Cut(string(raw), ":")
	if !ok {
		return
	}
	if *clientID == "" {
		*clientID, _ = url.QueryUnescape(left)
	}
	if *clientSecret == "" {
		*clientSecret, _ = url.QueryUnescape(right)
	}
}

func tokenFromRequest(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return ""
}

func requireSecretKey(c *corehttp.Context) bool {
	token := tokenFromRequest(c.Request)
	if strings.HasPrefix(token, "sk_test_") || strings.HasPrefix(token, "sk_live_") {
		return true
	}
	clerkError(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication failed", "Invalid or missing secret key")
	return false
}

func clerkError(c *corehttp.Context, status int, code string, message string, longMessage ...string) {
	long := message
	if len(longMessage) > 0 && longMessage[0] != "" {
		long = longMessage[0]
	}
	c.JSON(status, map[string]any{
		"errors": []map[string]any{
			{
				"code":         code,
				"message":      message,
				"long_message": long,
				"meta":         map[string]any{},
			},
		},
	})
}

func oauthError(c *corehttp.Context, status int, code string, description string) {
	c.JSON(status, map[string]any{"error": code, "error_description": description})
}

func deletedResponse(objectID string) map[string]any {
	return map[string]any{
		"object":  "deleted_object",
		"id":      objectID,
		"slug":    nil,
		"deleted": true,
	}
}

func paginatedResponse(data []map[string]any, totalCount int, limit int, offset int) map[string]any {
	return map[string]any{
		"data":        data,
		"total_count": totalCount,
		"has_more":    offset+limit < totalCount,
	}
}

func parsePagination(c *corehttp.Context) (int, int) {
	limit := intValue(c.Query("limit"))
	if limit < 1 {
		limit = 10
	}
	if limit > 500 {
		limit = 500
	}
	offset := intValue(c.Query("offset"))
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func verifyPKCE(challenge string, method string, verifier string) bool {
	if challenge == "" {
		return true
	}
	if verifier == "" {
		return false
	}
	switch strings.ToLower(method) {
	case "", "plain":
		return verifier == challenge
	case "s256":
		digest := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(digest[:]) == challenge
	default:
		return false
	}
}

func constantTimeEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func matchesRedirectURI(input string, allowed []string) bool {
	normalized := normalizeRedirectURI(input)
	for _, candidate := range allowed {
		if normalized == normalizeRedirectURI(candidate) {
			return true
		}
	}
	return false
}

func normalizeRedirectURI(value string) string {
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/")
	}
	return strings.TrimRight(strings.Split(value, "?")[0], "/")
}

func slugify(value string) string {
	lower := strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func sortNewestFirst(records []corestore.Record) []corestore.Record {
	out := append([]corestore.Record(nil), records...)
	sort.SliceStable(out, func(i int, j int) bool {
		return int64Field(out[i], "created_at_unix") > int64Field(out[j], "created_at_unix")
	})
	return out
}

func sliceRecords(records []corestore.Record, limit int, offset int) []corestore.Record {
	if offset > len(records) {
		offset = len(records)
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	return records[offset:end]
}
