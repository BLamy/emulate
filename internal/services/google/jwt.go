package google

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

var googleJWTSecret = []byte("emulate-google-jwt-secret")

func signIDToken(user map[string]any, clientID string, nonce string, issuer string) string {
	now := time.Now()
	claims := map[string]any{
		"iss":            issuer,
		"aud":            clientID,
		"sub":            stringValue(user["uid"]),
		"email":          stringValue(user["email"]),
		"email_verified": user["email_verified"],
		"name":           stringValue(user["name"]),
		"given_name":     stringValue(user["given_name"]),
		"family_name":    stringValue(user["family_name"]),
		"picture":        user["picture"],
		"locale":         stringValue(user["locale"]),
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	if hd := stringValue(user["hd"]); hd != "" {
		claims["hd"] = hd
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	headerRaw, _ := json.Marshal(header)
	claimRaw, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(claimRaw)
	mac := hmac.New(sha256.New, googleJWTSecret)
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
