// Command soulfold is the fold: the Soulstream ecosystem's default
// identity provider — a passkey-first OIDC issuer on a JetStream-backed
// sealed store, standing where any other OIDC provider may stand
// instead.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/impire-io/soulfold/embed"
	"github.com/impire-io/soulfold/internal/serve"
	"github.com/impire-io/soulfold/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "soulfold:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println(version.Version)
		return nil
	case "serve":
		return cmdServe(args[1:])
	case "seed":
		return cmdSeed(args[1:])
	case "invite":
		return cmdInvite(args[1:])
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, `usage:
  soulfold serve  --issuer URL --state-dir DIR [--listen ADDR] [--nats-url URL] [--token-audience AUD] [--enable-dcr]
  soulfold seed user   --state-dir DIR --username NAME [--display-name NAME] [--roles A,B] [--nats-url URL]
  soulfold seed client --state-dir DIR --client-id ID --redirect-uri URI[,URI...] [--name NAME] [--nats-url URL]
  soulfold invite --state-dir DIR --username NAME [--ttl 24h] [--nats-url URL]
  soulfold version`)
	return fmt.Errorf("unknown or missing command")
}

// cmdInvite is the operator act (D22): possession of the deployment's
// state mints an enrollment invite — the same trust that founded the
// fold. The token prints once; the store keeps only its digest.
func cmdInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "directory for the seal seed and the embedded store")
	natsURL := fs.String("nats-url", "", "external JetStream server (default: embedded)")
	username := fs.String("username", "", "user to invite")
	ttl := fs.Duration("ttl", 0, "invite lifetime (default 24h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("invite: --username is required")
	}
	ctx := context.Background()
	f, err := serve.Open(ctx, serve.Options{
		Issuer: "http://127.0.0.1:0", Listen: "127.0.0.1:0",
		StateDir: *stateDir, NATSURL: *natsURL,
	})
	if err != nil {
		return err
	}
	defer f.Close()
	token, err := f.Lifecycle.MintInvite(ctx, *username, *ttl)
	if err != nil {
		return err
	}
	fmt.Printf("invite for %s (single use, shown once):\n  %s\nenroll at: <issuer>/login/?invite=%s\n", *username, token, token)
	return nil
}

// cmdServe runs the fold through the public embed seam — the daemon is
// the seam's first consumer (the ecosystem's D29 discipline).
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	issuer := fs.String("issuer", "", "public issuer URL (its host becomes WebAuthn's one-way door at first enrollment)")
	stateDir := fs.String("state-dir", "", "directory for the seal seed and the embedded store")
	listen := fs.String("listen", "", "listen address (default: the issuer's host:port)")
	natsURL := fs.String("nats-url", "", "external JetStream server (default: embedded)")
	tokenAudience := fs.String("token-audience", "", "fixed audience joined to every issued token (the resource deployment's value)")
	enableDCR := fs.Bool("enable-dcr", false, "serve RFC 7591 dynamic client registration at /register")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return embed.Run(ctx, embed.Options{
		Issuer: *issuer, Listen: *listen, StateDir: *stateDir, NATSURL: *natsURL,
		TokenAudience: *tokenAudience, EnableDCR: *enableDCR,
		Ready: func(addr string) {
			fmt.Printf("soulfold %s serving %s on %s\n", version.Version, *issuer, addr)
		},
	})
}

// cmdSeed opens the store the same way serve does (no HTTP listener
// worth keeping) and writes the M1 stand-in records through the store's
// public surfaces.
func cmdSeed(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	kind := args[0]
	fs := flag.NewFlagSet("seed "+kind, flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "directory for the seal seed and the embedded store")
	natsURL := fs.String("nats-url", "", "external JetStream server (default: embedded)")
	username := fs.String("username", "", "username to seed (seed user)")
	displayName := fs.String("display-name", "", "display name (seed user)")
	roles := fs.String("roles", "", "comma-separated roles-claim values (seed user)")
	clientID := fs.String("client-id", "", "client id to seed (seed client)")
	name := fs.String("name", "", "client display name (seed client)")
	redirectURIs := fs.String("redirect-uri", "", "comma-separated redirect URIs (seed client)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	ctx := context.Background()
	f, err := serve.Open(ctx, serve.Options{
		Issuer: "http://127.0.0.1:0", Listen: "127.0.0.1:0",
		StateDir: *stateDir, NATSURL: *natsURL,
	})
	if err != nil {
		return err
	}
	defer f.Close()

	switch kind {
	case "user":
		if *username == "" {
			return fmt.Errorf("seed user: --username is required")
		}
		var roleList []string
		if *roles != "" {
			roleList = strings.Split(*roles, ",")
		}
		u, err := serve.SeedUser(ctx, f.Store, *username, *displayName, roleList...)
		if err != nil {
			return err
		}
		fmt.Printf("seeded user %s (%s)\n", u.Username, u.ID)
		return nil
	case "client":
		if *clientID == "" || *redirectURIs == "" {
			return fmt.Errorf("seed client: --client-id and --redirect-uri are required")
		}
		c, err := serve.SeedClient(ctx, f.Store, *clientID, *name, strings.Split(*redirectURIs, ","))
		if err != nil {
			return err
		}
		fmt.Printf("seeded client %s\n", c.ClientID)
		return nil
	default:
		return usage()
	}
}
