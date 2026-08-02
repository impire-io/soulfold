// Package serve assembles the fold: store (embedded or external NATS),
// envelope, key lifecycle, provider, and the two-page UI on one HTTP
// listener. M5 lifts this assembly into the public embed seam; until
// then it is internal on purpose.
package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/impire-io/soulfold/internal/envelope"
	"github.com/impire-io/soulfold/internal/keys"
	"github.com/impire-io/soulfold/internal/natsserver"
	"github.com/impire-io/soulfold/internal/passkeys"
	"github.com/impire-io/soulfold/internal/provider"
	"github.com/impire-io/soulfold/internal/store"
	"github.com/impire-io/soulfold/internal/ui"
)

// Options configure one fold instance. Value-only, the ecosystem's
// embed convention (soulidentity D29) ahead of M5's public seam.
type Options struct {
	// Issuer is the public URL consumers know the fold by. WebAuthn will
	// make its host a one-way door at first enrollment (D14) — deployment
	// docs say so, loudly.
	Issuer string
	// Listen is the address to serve on (host:port). Empty means the
	// issuer's host:port.
	Listen string
	// StateDir holds the seal seed and, when NATSURL is empty, the
	// embedded server's store directory (under <StateDir>/jetstream —
	// the seed stays outside it, D17).
	StateDir string
	// NATSURL, when set, uses an external JetStream server instead of
	// the embedded one. NATSCreds optionally names a creds file for it
	// (operator-mode parents; the embedded server needs none).
	NATSURL   string
	NATSCreds string
	// BucketPrefix overrides the default bucket prefix (D1).
	BucketPrefix string
	// TokenAudience, when set, joins every issued token's aud alongside
	// the client id — the fixed value a resource deployment (the door
	// AS contract §3) validates. Empty keeps the plain-RP default.
	TokenAudience string
	// EnableDCR serves RFC 7591 dynamic client registration at
	// /register (public clients, PKCE): what hosted MCP clients expect
	// of an authorization server. Off by default — a plain RP
	// deployment registers its clients deliberately.
	EnableDCR bool
}

// Fold is a running instance.
type Fold struct {
	Store *store.Store
	Keys  *keys.Service

	httpSrv *http.Server
	ln      net.Listener
	nc      *nats.Conn
	ns      *server.Server
}

// Open brings up everything except the HTTP listener's Serve loop —
// callers decide whether Run blocks (CLI) or runs beside them (tests,
// embedding).
func Open(ctx context.Context, opts Options) (*Fold, error) {
	if opts.Issuer == "" || opts.StateDir == "" {
		return nil, errors.New("serve: Issuer and StateDir are required")
	}
	issuerURL, err := url.Parse(opts.Issuer)
	if err != nil || issuerURL.Host == "" {
		return nil, fmt.Errorf("serve: issuer %q is not a URL", opts.Issuer)
	}

	sealer, err := envelope.LoadOrCreate(filepath.Join(opts.StateDir, "seal.xkey"))
	if err != nil {
		return nil, err
	}

	f := &Fold{}
	natsURL := opts.NATSURL
	if natsURL == "" {
		ns, err := natsserver.Start(filepath.Join(opts.StateDir, "jetstream"))
		if err != nil {
			return nil, err
		}
		f.ns = ns
		natsURL = ns.ClientURL()
	}
	var connectOpts []nats.Option
	if opts.NATSCreds != "" {
		connectOpts = append(connectOpts, nats.UserCredentials(opts.NATSCreds))
	}
	nc, err := nats.Connect(natsURL, connectOpts...)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("serve: connect %s: %w", natsURL, err)
	}
	f.nc = nc
	js, err := jetstream.New(nc)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("serve: jetstream: %w", err)
	}
	st, err := store.Open(ctx, js, sealer, opts.BucketPrefix)
	if err != nil {
		f.Close()
		return nil, err
	}
	f.Store = st
	f.Keys = &keys.Service{St: st}
	if err := f.Keys.EnsureFirstKey(ctx); err != nil {
		f.Close()
		return nil, err
	}

	p, err := provider.New(opts.Issuer, opts.TokenAudience, st, f.Keys)
	if err != nil {
		f.Close()
		return nil, err
	}
	pk, err := passkeys.New(st, issuerURL)
	if err != nil {
		f.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/", p)
	uiHandler := &ui.Handler{St: st, Passkeys: pk, Issuer: issuerURL, Callback: op.AuthCallbackURL(p)}
	uiHandler.Register(mux)
	if opts.EnableDCR {
		registerDCR(mux, p, opts.Issuer, st)
	}

	listen := opts.Listen
	if listen == "" {
		listen = issuerURL.Host
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("serve: listen %s: %w", listen, err)
	}
	f.ln = ln
	f.httpSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return f, nil
}

// Run serves until ctx ends, then shuts down cleanly.
func (f *Fold) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- f.httpSrv.Serve(f.ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.httpSrv.Shutdown(shutdownCtx)
		f.Close()
		return nil
	case err := <-errCh:
		f.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Addr is the bound listen address (tests use :0).
func (f *Fold) Addr() string {
	if f.ln == nil {
		return ""
	}
	return f.ln.Addr().String()
}

// Close tears the instance down: HTTP first, then the connection, then
// the embedded server (when one runs). Idempotent.
func (f *Fold) Close() {
	if f.httpSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = f.httpSrv.Shutdown(shutdownCtx)
		cancel()
		f.httpSrv = nil
	} else if f.ln != nil {
		_ = f.ln.Close()
	}
	f.ln = nil
	if f.nc != nil {
		f.nc.Close()
		f.nc = nil
	}
	if f.ns != nil {
		f.ns.Shutdown()
		f.ns.WaitForShutdown()
		f.ns = nil
	}
}

// SeedUser creates the M1 stand-in user (roadmap: "a seeded user and
// client standing in for the ceremonies"; M3 replaces seeding with the
// lifecycle). Roles surface as the token's roles-claim values.
// The id shape (u-hex, no underscores) is a consumer-proven constraint:
// it doubles as a soulstream persona name downstream, and that grammar
// admits lowercase alphanumerics and hyphens only.
func SeedUser(ctx context.Context, st *store.Store, username, displayName string, roles ...string) (store.User, error) {
	now := store.Now()
	u := store.User{
		Schema: 1, ID: "u-" + store.RandID(8), Username: username,
		DisplayName: displayName, Status: "active", Roles: roles,
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := st.Create(ctx, st.Users, u.ID, u); err != nil {
		return store.User{}, err
	}
	if _, err := st.Create(ctx, st.Users, store.UsernameIndexKey(username), store.Index{Schema: 1, Target: u.ID}); err != nil {
		return store.User{}, err
	}
	return u, nil
}

// SeedClient creates the M1 stand-in public client.
func SeedClient(ctx context.Context, st *store.Store, clientID, name string, redirectURIs []string) (store.Client, error) {
	c := store.Client{
		Schema: 1, ClientID: clientID, Name: name,
		RedirectURIs: redirectURIs, Public: true, CreatedAt: store.Now(),
	}
	if _, err := st.Create(ctx, st.Clients, c.ClientID, c); err != nil {
		return store.Client{}, err
	}
	return c, nil
}
