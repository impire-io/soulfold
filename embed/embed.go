// Package embed is the operator surface of the fold: it assembles and
// runs what `soulfold serve` runs — the OIDC provider, the passkey
// ceremonies, and the sealed store — inside the caller's own process
// (the ecosystem's embed pattern, soulidentity D29; roadmap M5). The
// single-binary distribution runs the fold through this seam; the
// daemon is its first consumer.
//
// Options are value-only and mirror the serve command's flags; no
// internal type appears here. Custody is unchanged: the seal seed is
// born into (or read from) StateDir exactly as the daemon does it —
// embedding changes where the fold runs, never what it stores
// (design D16–D17).
package embed

import (
	"context"
	"fmt"

	"github.com/impire-io/soulfold/internal/serve"
	"github.com/impire-io/soulfold/internal/store"
)

// Options describes one fold assembly, by value.
type Options struct {
	// Issuer is the public URL consumers know the fold by. WebAuthn
	// makes its host a one-way door at first enrollment (D14).
	Issuer string
	// Listen is the address to serve on. Empty: the issuer's host:port.
	Listen string
	// StateDir holds the seal seed and, when NATSURL is empty, the
	// embedded JetStream server's store (the seed stays outside it).
	StateDir string
	// NATSURL, when set, stores on an external JetStream server the
	// caller operates instead of an embedded one.
	NATSURL string
	// BucketPrefix overrides the default bucket prefix (D1).
	BucketPrefix string
	// TokenAudience, when set, joins every issued token's aud alongside
	// the client id — what a resource deployment validates.
	TokenAudience string
	// EnableDCR serves RFC 7591 dynamic client registration — what
	// hosted MCP clients expect of an authorization server.
	EnableDCR bool

	// SeedUsers and SeedClients are the M1-era stand-ins for the M3
	// lifecycle: records created at startup when absent, so an
	// embedding distribution can found its first user and client in
	// the same act that starts the fold. Existing records are left
	// untouched.
	SeedUsers   []SeedUser
	SeedClients []SeedClient

	// Ready, when non-nil, receives the bound listen address once the
	// fold serves (tests and parents that need the real port).
	Ready func(addr string)
}

// SeedUser is a user stand-in (M3 replaces seeding with the lifecycle).
// Roles surface as the user's tokens' roles-claim values.
type SeedUser struct {
	Username    string
	DisplayName string
	Roles       []string
}

// SeedClient is a pre-registered public PKCE client.
type SeedClient struct {
	ClientID     string
	Name         string
	RedirectURIs []string
}

// Run assembles and serves the fold until ctx ends. It returns nil on a
// clean ctx-driven shutdown and the failing stage's error otherwise.
func Run(ctx context.Context, o Options) error {
	f, err := serve.Open(ctx, serve.Options{
		Issuer: o.Issuer, Listen: o.Listen, StateDir: o.StateDir,
		NATSURL: o.NATSURL, BucketPrefix: o.BucketPrefix,
		TokenAudience: o.TokenAudience, EnableDCR: o.EnableDCR,
	})
	if err != nil {
		return err
	}
	for _, u := range o.SeedUsers {
		if _, err := serve.SeedUser(ctx, f.Store, u.Username, u.DisplayName, u.Roles...); err != nil {
			if !isExists(err) {
				f.Close()
				return fmt.Errorf("embed: seed user %s: %w", u.Username, err)
			}
		}
	}
	for _, c := range o.SeedClients {
		if _, err := serve.SeedClient(ctx, f.Store, c.ClientID, c.Name, c.RedirectURIs); err != nil {
			if !isExists(err) {
				f.Close()
				return fmt.Errorf("embed: seed client %s: %w", c.ClientID, err)
			}
		}
	}
	if o.Ready != nil {
		o.Ready(f.Addr())
	}
	return f.Run(ctx)
}

// isExists reports the create-refusal of an already-present record —
// the seeding idempotency case (D4: birth by Create, duplicates are
// errors, and here deliberately tolerated).
func isExists(err error) bool {
	return err != nil && store.IsAlreadyExists(err)
}
