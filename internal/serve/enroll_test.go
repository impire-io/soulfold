package serve_test

// The standalone enrolment gate: an invite link (`/enroll?invite=…`)
// enrols a passkey with no relying party and no OIDC request — the
// invite is the whole capability. After enrolment the user can sign in
// through any RP; the invite is single-use.

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

func TestStandaloneEnroll(t *testing.T) {
	ctx := context.Background()
	addr := reservePort(t)
	issuer := "http://" + addr
	fold, err := serve.Open(ctx, serve.Options{Issuer: issuer, Listen: addr, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fold.Close()
	go func() { _ = fold.Run(ctx) }()

	if _, err := serve.SeedUser(ctx, fold.Store, "dana", "Dana"); err != nil {
		t.Fatal(err)
	}
	invite, err := fold.Lifecycle.MintInvite(ctx, "dana", 0)
	if err != nil {
		t.Fatal(err)
	}

	// The bare enrol page renders (no OIDC request needed), naming the
	// invite's user in a read-only field — the username is the invite's
	// fact, not the visitor's choice.
	resp, err := http.Get(issuer + "/enroll?invite=" + invite)
	if err != nil {
		t.Fatal(err)
	}
	page := body(t, resp)
	if !strings.Contains(page, "Enroll your passkey") {
		t.Fatalf("enrol page did not render:\n%s", page[:clip(200, len(page))])
	}
	if !strings.Contains(page, `value="dana" readonly`) {
		t.Fatalf("enrol page did not pin the invited username read-only:\n%s", page[:clip(2000, len(page))])
	}

	// A dead link is refused at the page, not at the ceremony.
	badResp, err := http.Get(issuer + "/enroll?invite=sfi_bogus")
	if err != nil {
		t.Fatal(err)
	}
	if badPage := body(t, badResp); badResp.StatusCode != http.StatusForbidden ||
		strings.Contains(badPage, "Enroll your passkey") {
		t.Fatalf("a bogus invite rendered the enrol form (%d)", badResp.StatusCode)
	}

	// Drive the enrolment ceremony through the /enroll endpoints.
	auth, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	q := url.Values{"username": {"dana"}, "invite": {invite}}
	begin, err := client.Post(issuer+"/enroll/begin?"+q.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		CeremonyID string          `json:"ceremonyID"`
		Options    json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(begin.Body).Decode(&b); err != nil {
		t.Fatalf("begin (%d): %v", begin.StatusCode, err)
	}
	_ = begin.Body.Close()
	waBody, err := auth.CreateResponse(b.Options)
	if err != nil {
		t.Fatal(err)
	}
	q.Set("ceremonyID", b.CeremonyID)
	fin, err := client.Post(issuer+"/enroll/finish?"+q.Encode(), "application/json", strings.NewReader(string(waBody)))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(fin.Body).Decode(&out); err != nil {
		t.Fatalf("finish (%d): %v", fin.StatusCode, err)
	}
	_ = fin.Body.Close()
	if !strings.Contains(out.Redirect, "/enroll?done") {
		t.Fatalf("enrolment redirect = %q", out.Redirect)
	}

	// Dana now has a credential, and the invite is spent.
	dana, err := fold.Lifecycle.UserByName(ctx, "dana")
	if err != nil {
		t.Fatal(err)
	}
	if len(dana.Credentials) != 1 {
		t.Fatalf("dana has %d credentials, want 1", len(dana.Credentials))
	}
	if _, _, _, err := fold.Passkeys.Begin(ctx, "dana", "authreq", invite); err == nil {
		t.Fatal("the spent invite still enrols")
	}

	// The confirmation page renders.
	doneResp, err := http.Get(issuer + "/enroll?done=1")
	if err != nil {
		t.Fatal(err)
	}
	if page := body(t, doneResp); !strings.Contains(page, "enrolled") {
		t.Fatal("confirmation page did not render")
	}
	_ = io.Discard
}
