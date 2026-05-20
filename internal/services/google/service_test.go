package google

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	corehttp "github.com/vercel-labs/emulate/internal/core/http"
	corestore "github.com/vercel-labs/emulate/internal/core/store"
)

func newGoogleTestHandler() http.Handler {
	router := corehttp.NewRouter()
	Register(router, Options{
		Store:   corestore.New(),
		BaseURL: "http://localhost:4016",
		Seed: &SeedConfig{
			Users: []UserSeed{
				{Email: "testuser@example.com", Name: "Test User"},
				{Email: "consumer@gmail.com", Name: "Consumer User"},
			},
			OAuthClients: []OAuthClientSeed{
				{
					ClientID:     "emu_google_client_id",
					ClientSecret: "emu_google_client_secret",
					Name:         "Inbox Zero",
					RedirectURIs: []string{"http://localhost:3000/api/auth/callback/google"},
				},
			},
			Labels: []LabelSeed{
				{ID: "Label_ops", UserEmail: "testuser@example.com", Name: "Ops/Review", ColorBackground: "#DDEEFF", ColorText: "#111111"},
			},
			Messages: []MessageSeed{
				{
					ID:        "msg_support_1",
					ThreadID:  "thread_support",
					UserEmail: "testuser@example.com",
					From:      "Support <support@example.com>",
					To:        "testuser@example.com",
					Subject:   "Your support ticket has been updated",
					BodyText:  "We have an update on your ticket.",
					LabelIDs:  []string{"INBOX", "UNREAD", "Label_ops"},
					Date:      "2025-01-04T10:00:00.000Z",
				},
				{
					ID:        "msg_invoice",
					ThreadID:  "thread_billing",
					UserEmail: "testuser@example.com",
					From:      "Billing <billing@example.com>",
					To:        "testuser@example.com",
					Subject:   "Invoice ready for review",
					BodyText:  "Your January invoice is ready to review.",
					LabelIDs:  []string{"INBOX", "CATEGORY_UPDATES"},
					Date:      "2025-01-03T10:00:00.000Z",
				},
				{
					ID:        "msg_draft",
					ThreadID:  "thread_draft",
					UserEmail: "testuser@example.com",
					From:      "testuser@example.com",
					To:        "partner@example.com",
					Subject:   "Draft follow-up",
					BodyText:  "Draft body.",
					LabelIDs:  []string{"DRAFT"},
					Date:      "2025-01-01T10:00:00.000Z",
				},
			},
			Calendars: []CalendarSeed{
				{ID: "primary", UserEmail: "testuser@example.com", Summary: "testuser@example.com", Primary: true, TimeZone: "UTC"},
				{ID: "cal_team", UserEmail: "testuser@example.com", Summary: "Team Calendar", TimeZone: "UTC"},
			},
			CalendarEvents: []CalendarEventSeed{
				{
					ID:            "evt_kickoff",
					UserEmail:     "testuser@example.com",
					CalendarID:    "primary",
					Summary:       "Project Kickoff",
					StartDateTime: "2025-01-10T09:00:00.000Z",
					EndDateTime:   "2025-01-10T09:30:00.000Z",
					HangoutLink:   "https://meet.google.com/project-kickoff",
				},
			},
			DriveItems: []DriveItemSeed{
				{ID: "drv_docs", UserEmail: "testuser@example.com", Name: "Docs", MIMEType: googleDriveFolderMIME, ParentIDs: []string{"root"}},
				{ID: "drv_handbook", UserEmail: "testuser@example.com", Name: "Handbook.pdf", MIMEType: "application/pdf", ParentIDs: []string{"drv_docs"}, Data: "pdf-handbook-data"},
			},
		},
	})
	return router
}

func TestGoogleOAuthAuthorizationCodeAndRefresh(t *testing.T) {
	handler := newGoogleTestHandler()
	form := url.Values{
		"email":        {"testuser@example.com"},
		"redirect_uri": {"http://localhost:3000/api/auth/callback/google"},
		"scope":        {"openid email profile https://www.googleapis.com/auth/calendar.readonly"},
		"client_id":    {"emu_google_client_id"},
	}
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://localhost:4016/o/oauth2/v2/auth/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusFound {
		t.Fatalf("authorize callback status = %d, body = %s", res.Code, res.Body.String())
	}
	location, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in redirect: %s", res.Header().Get("Location"))
	}

	tokenForm := url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"http://localhost:3000/api/auth/callback/google"},
		"client_id":     {"emu_google_client_id"},
		"client_secret": {"emu_google_client_secret"},
	}
	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://localhost:4016/oauth2/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", res.Code, res.Body.String())
	}
	var tokenBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Scope        string `json:"scope"`
	}
	mustDecodeGoogleJSON(t, res.Body.Bytes(), &tokenBody)
	if !strings.HasPrefix(tokenBody.AccessToken, "google_") || !strings.HasPrefix(tokenBody.RefreshToken, "google_refresh_") || tokenBody.IDToken == "" {
		t.Fatalf("unexpected token body: %#v", tokenBody)
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenBody.RefreshToken},
		"client_id":     {"emu_google_client_id"},
		"client_secret": {"emu_google_client_secret"},
	}
	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://localhost:4016/oauth2/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", res.Code, res.Body.String())
	}
	var refreshBody struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	mustDecodeGoogleJSON(t, res.Body.Bytes(), &refreshBody)
	if refreshBody.AccessToken == "" || refreshBody.AccessToken == tokenBody.AccessToken || refreshBody.Scope != tokenBody.Scope {
		t.Fatalf("unexpected refresh body: %#v", refreshBody)
	}
}

func TestGoogleGmailCalendarAndDriveSeededRoutes(t *testing.T) {
	handler := newGoogleTestHandler()
	res := googleRequest(handler, http.MethodGet, "/oauth2/v2/userinfo", "", true)
	if res.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"email":"testuser@example.com"`) || !strings.Contains(res.Body.String(), `"hd":"example.com"`) {
		t.Fatalf("unexpected userinfo: %s", res.Body.String())
	}

	res = googleRequest(handler, http.MethodGet, "/gmail/v1/users/me/messages?maxResults=2&q=-label:DRAFT+in:inbox", "", true)
	if res.Code != http.StatusOK {
		t.Fatalf("messages status = %d, body = %s", res.Code, res.Body.String())
	}
	var messages struct {
		Messages []struct {
			ID       string `json:"id"`
			ThreadID string `json:"threadId"`
		} `json:"messages"`
		ResultSizeEstimate int `json:"resultSizeEstimate"`
	}
	mustDecodeGoogleJSON(t, res.Body.Bytes(), &messages)
	if messages.ResultSizeEstimate != 2 || messages.Messages[0].ID != "msg_support_1" || messages.Messages[1].ID != "msg_invoice" {
		t.Fatalf("unexpected messages: %#v", messages)
	}

	res = googleRequest(handler, http.MethodPost, "/gmail/v1/users/me/messages/msg_invoice/modify", `{"addLabelIds":["Label_ops"],"removeLabelIds":["INBOX"]}`, true)
	if res.Code != http.StatusOK {
		t.Fatalf("modify status = %d, body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"Label_ops"`) || strings.Contains(res.Body.String(), `"INBOX"`) {
		t.Fatalf("unexpected modified message: %s", res.Body.String())
	}

	res = googleRequest(handler, http.MethodPost, "/gmail/v1/users/me/drafts", `{"message":{"to":"partner@example.com","subject":"Draft review","text":"First draft body"}}`, true)
	if res.Code != http.StatusOK {
		t.Fatalf("create draft status = %d, body = %s", res.Code, res.Body.String())
	}
	var draft struct {
		ID      string `json:"id"`
		Message struct {
			ID       string   `json:"id"`
			LabelIDs []string `json:"labelIds"`
		} `json:"message"`
	}
	mustDecodeGoogleJSON(t, res.Body.Bytes(), &draft)
	if draft.ID == "" || !containsString(draft.Message.LabelIDs, "DRAFT") {
		t.Fatalf("unexpected draft: %#v", draft)
	}
	res = googleRequest(handler, http.MethodPost, "/gmail/v1/users/me/drafts/send", `{"id":"`+draft.ID+`"}`, true)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"SENT"`) || strings.Contains(res.Body.String(), `"DRAFT"`) {
		t.Fatalf("send draft status = %d, body = %s", res.Code, res.Body.String())
	}

	res = googleRequest(handler, http.MethodGet, "/calendar/v3/users/me/calendarList", "", true)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"id":"primary"`) || !strings.Contains(res.Body.String(), `"id":"cal_team"`) {
		t.Fatalf("calendar list status = %d, body = %s", res.Code, res.Body.String())
	}

	res = googleRequest(handler, http.MethodGet, "/calendar/v3/calendars/primary/events?q=kickoff", "", true)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"id":"evt_kickoff"`) {
		t.Fatalf("event list status = %d, body = %s", res.Code, res.Body.String())
	}

	res = googleRequest(handler, http.MethodGet, "/drive/v3/files?q=%27root%27+in+parents+and+mimeType+%3D+%27application%2Fvnd.google-apps.folder%27+and+trashed+%3D+false", "", true)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"id":"drv_docs"`) {
		t.Fatalf("drive list status = %d, body = %s", res.Code, res.Body.String())
	}

	res = googleRequest(handler, http.MethodGet, "/drive/v3/files/drv_handbook?alt=media", "", true)
	if res.Code != http.StatusOK {
		t.Fatalf("drive media status = %d, body = %s", res.Code, res.Body.String())
	}
	body, _ := io.ReadAll(res.Result().Body)
	if string(body) != "pdf-handbook-data" {
		t.Fatalf("unexpected drive media body: %q", string(body))
	}
}

func googleRequest(handler http.Handler, method string, path string, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://localhost:4016"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func mustDecodeGoogleJSON(t *testing.T, raw []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, string(raw))
	}
}
