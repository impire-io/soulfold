// Command soulfold is the fold: the Soulstream ecosystem's default identity
// provider — a passkey-first OIDC issuer on a JetStream-backed store, standing
// where any other OIDC provider may stand instead.
//
// The serve assembly arrives with M1 (hq/03-IMPLEMENTATION/ROADMAP.md); until
// then the binary reports its version and nothing else.
package main

import (
	"fmt"
	"os"

	"github.com/impire-io/soulfold/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "soulfold: pre-M1 skeleton — the roadmap lives in hq/03-IMPLEMENTATION/ROADMAP.md")
	os.Exit(2)
}
