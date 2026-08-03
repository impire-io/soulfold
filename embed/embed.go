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
	// caller operates instead of an embedded one. NATSCreds optionally
	// names a creds file for it (operator-mode parents).
	NATSURL   string
	NATSCreds string
	// BucketPrefix overrides the default bucket prefix (D1).
	BucketPrefix string
	// TokenAudience, when set, joins every issued token's aud alongside
	// the client id — what a resource deployment validates.
	TokenAudience string
	// EnableDCR serves RFC 7591 dynamic client registration — what
	// hosted MCP clients expect of an authorization server.
	EnableDCR bool

	// SeedUsers and SeedClients found the fold's first records at
	// startup when absent (idempotent; existing records untouched).
	// Since M3, seeding grants existence, never enrollment: a seeded
	// user signs in only after an invite enrolls their passkey (D20).
	SeedUsers   []SeedUser
	SeedClients []SeedClient

	// InviteSink, when non-nil, receives a freshly minted single-use
	// enrollment invite for every seeded user who has no credential
	// and no live invite yet — the embedding parent owns its custody
	// (print once, hand out-of-band; never log it). The bearer exists
	// nowhere else: the store keeps only its digest (D21).
	InviteSink func(username, token string)

	// Ready, when non-nil, receives the bound listen address once the
	// fold serves (tests and parents that need the real port).
	Ready func(addr string)
}

// SeedUser is a founding user. Roles are group memberships (M3): the
// names surface as the user's tokens' roles-claim values.
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
		NATSURL: o.NATSURL, NATSCreds: o.NATSCreds, BucketPrefix: o.BucketPrefix,
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
		if o.InviteSink != nil {
			user, err := f.Lifecycle.UserByName(ctx, u.Username)
			if err != nil {
				f.Close()
				return fmt.Errorf("embed: seed user %s: %w", u.Username, err)
			}
			if len(user.Credentials) == 0 {
				live, err := f.Lifecycle.HasLiveInvite(ctx, user.ID)
				if err != nil {
					f.Close()
					return fmt.Errorf("embed: invite check for %s: %w", u.Username, err)
				}
				if !live {
					token, err := f.Lifecycle.MintInvite(ctx, u.Username, 0)
					if err != nil {
						f.Close()
						return fmt.Errorf("embed: mint invite for %s: %w", u.Username, err)
					}
					o.InviteSink(u.Username, token)
				}
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
