package serve_test

// The admin console gate (D25): an administrator signs into /admin with
// their passkey — a session-only ceremony, no relying party — and
// drives the lifecycle from a browser: create a person, mint their
// enrolment invite, put them in a group, disable them. A non-admin's
// passkey is refused at the console door; an unauthenticated request
// sees the login page, never the dashboard; a forged CSRF changes
// nothing.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/internal/serve"
)

func TestAdminConsole(t *testing.T) {
	ctx := context.Background()
	addr := reservePort(t)
	issuer := "http://" + addr
	fold, err := serve.Open(ctx, serve.Options{Issuer: issuer, Listen: addr, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fold.Close()
	go func() { _ = fold.Run(ctx) }()

	// An enrolled admin and an enrolled ordinary user.
	admin := enroll(ctx, t, fold, issuer, "root", "admin")
	ordinary := enroll(ctx, t, fold, issuer, "nobody")

	// Unauthenticated: /admin/ shows the login page, not the dashboard.
	resp, err := http.Get(issuer + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	page := body(t, resp)
	if !strings.Contains(page, "Administrator sign-in") {
		t.Fatalf("unauthenticated /admin/ did not render the login page:\n%s", page[:clip(300, len(page))])
	}
	if strings.Contains(page, "Add a person") {
		t.Fatal("unauthenticated request saw the dashboard")
	}

	// The ordinary user's passkey is refused at the console.
	if _, ok := consoleLogin(t, issuer, ordinary, "nobody"); ok {
		t.Fatal("a non-admin signed into the console")
	}

	// The admin signs in and lands on the dashboard.
	adminClient, ok := consoleLogin(t, issuer, admin, "root")
	if !ok {
		t.Fatal("the admin could not sign into the console")
	}
	dash := consoleGet(t, adminClient, issuer+"/admin/")
	if !strings.Contains(dash, "Add a person") || !strings.Contains(dash, "signed in as root") {
		t.Fatalf("dashboard missing after admin login:\n%s", dash[:clip(400, len(dash))])
	}
	csrf := extractValue(t, dash, "csrf")

	// Create a person from the console.
	consolePost(t, adminClient, issuer+"/admin/users", url.Values{
		"csrf": {csrf}, "username": {"erin"}, "display_name": {"Erin"}, "groups": {"engineering"},
	})
	dash = consoleGet(t, adminClient, issuer+"/admin/")
	if !strings.Contains(dash, "erin") {
		t.Fatal("the created user does not appear on the dashboard")
	}

	// Mint erin's invite from the console — the enrol link is shown once.
	after := consolePost(t, adminClient, issuer+"/admin/users/erin/invite", url.Values{"csrf": {csrf}})
	if !strings.Contains(after, "/login/?invite=sfi_") {
		t.Fatalf("the console did not surface an enrolment link:\n%s", after[:clip(400, len(after))])
	}

	// Move erin into a group, then disable her — both from the console.
	consolePost(t, adminClient, issuer+"/admin/users/erin/groups", url.Values{"csrf": {csrf}, "groups": {"platform"}})
	consolePost(t, adminClient, issuer+"/admin/users/erin/status", url.Values{"csrf": {csrf}, "status": {"disabled"}})
	erin, err := fold.Lifecycle.UserByName(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	if erin.Status != "disabled" || len(erin.Groups) != 1 || erin.Groups[0] != "platform" {
		t.Fatalf("console edits did not land: status=%s groups=%v", erin.Status, erin.Groups)
	}

	// A forged CSRF changes nothing.
	consolePost(t, adminClient, issuer+"/admin/users", url.Values{
		"csrf": {"forged"}, "username": {"ghost"},
	})
	if _, err := fold.Lifecycle.UserByName(ctx, "ghost"); err == nil {
		t.Fatal("a forged-CSRF create succeeded")
	}
}

// enroll creates a user (with optional groups) and drives one invite +
// registration ceremony, returning the authenticator holding the passkey.
func enroll(ctx context.Context, t *testing.T, fold *serve.Fold, issuer, username string, groups ...string) *authtest.Authenticator {
	t.Helper()
	if _, err := serve.SeedUser(ctx, fold.Store, username, username, groups...); err != nil {
		t.Fatal(err)
	}
	invite, err := fold.Lifecycle.MintInvite(ctx, username, 0)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	cerID, kind, options, err := fold.Passkeys.Begin(ctx, username, "", invite)
	if err != nil || kind != "register" {
		t.Fatalf("enroll begin %s: kind=%s err=%v", username, kind, err)
	}
	waBody, err := auth.CreateResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, issuer+"/login/finish", strings.NewReader(string(waBody)))
	req.Header.Set("Content-Type", "application/json")
	if _, _, err := fold.Passkeys.Finish(ctx, cerID, req); err != nil {
		t.Fatalf("enroll finish %s: %v", username, err)
	}
	return auth
}

// consoleLogin runs the /admin passkey assertion and returns a cookie
// jar client if it succeeded (admin) — ok is false when the console
// refuses (non-admin).
func consoleLogin(t *testing.T, issuer string, auth *authtest.Authenticator, username string) (*http.Client, bool) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	begin, err := client.Post(issuer+"/admin/login/begin?username="+username, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if begin.StatusCode != http.StatusOK {
		return nil, false
	}
	var b struct {
		CeremonyID string          `json:"ceremonyID"`
		Options    json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(begin.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	_ = begin.Body.Close()
	waBody, err := auth.GetResponse(b.Options)
	if err != nil {
		t.Fatal(err)
	}
	fin, err := client.Post(issuer+"/admin/login/finish?ceremonyID="+b.CeremonyID, "application/json", strings.NewReader(string(waBody)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, fin.Body)
	_ = fin.Body.Close()
	return client, fin.StatusCode == http.StatusOK
}

func consoleGet(t *testing.T, client *http.Client, u string) string {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return body(t, resp)
}

func consolePost(t *testing.T, client *http.Client, u string, form url.Values) string {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	return body(t, resp)
}

// extractValue pulls a name="..." value="..." out of rendered HTML.
func extractValue(t *testing.T, page, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no %s field in page", name)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func clip(a, b int) int {
	if a < b {
		return a
	}
	return b
}
