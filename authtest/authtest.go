// Package authtest is a virtual WebAuthn authenticator for test gates —
// the fold's own and any consumer's (an embedding distribution proving
// its bundled sign-in, an RP proving its integration). It performs real
// create/get ceremonies in-process: ES256 key pair, honest rpIdHash,
// flags, counters, ASN.1 signatures, CBOR "none" attestation. The one
// thing it cannot prove is a human touching hardware; the M2
// quickstart's runbook covers that half. Not for production use — a
// real deployment's credentials live in real authenticators.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is one virtual passkey bound to an RP ID and origin.
type Authenticator struct {
	RPID    string
	Origin  string
	Key     *ecdsa.PrivateKey
	CredID  []byte
	Counter uint32
	UserID  []byte
}

// New creates a virtual passkey for the RP.
func New(rpID, origin string) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}
	return &Authenticator{RPID: rpID, Origin: origin, Key: key, CredID: credID}, nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type publicKeyOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func clientData(typ, challenge, origin string) []byte {
	data, _ := json.Marshal(map[string]string{
		"type": typ, "challenge": challenge, "origin": origin,
	})
	return data
}

// xy returns the raw P-256 coordinates from the uncompressed point
// encoding (0x04 || X || Y).
func (a *Authenticator) xy() (x, y []byte, err error) {
	raw, err := a.Key.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return raw[1:33], raw[33:65], nil
}

// PublicX is the raw X coordinate — the positive-control needle for
// "is public key material findable in the store" scans.
func (a *Authenticator) PublicX() []byte {
	x, _, err := a.xy()
	if err != nil {
		panic(err)
	}
	return x
}

// PrivateScalar is the raw private key — the needle that must appear
// nowhere in the store (constitution I).
func (a *Authenticator) PrivateScalar() []byte {
	raw, err := a.Key.Bytes()
	if err != nil {
		panic(err)
	}
	return raw
}

// coseKey encodes the public key as a COSE EC2 ES256 key.
func (a *Authenticator) coseKey() ([]byte, error) {
	x, y, err := a.xy()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: x,
		-3: y,
	})
}

func (a *Authenticator) authData(flags byte, attested bool) ([]byte, error) {
	rpHash := sha256.Sum256([]byte(a.RPID))
	out := make([]byte, 0, 128)
	out = append(out, rpHash[:]...)
	out = append(out, flags)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.Counter)
	out = append(out, counter[:]...)
	if attested {
		out = append(out, make([]byte, 16)...) // zero AAGUID
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(a.CredID)))
		out = append(out, l[:]...)
		out = append(out, a.CredID...)
		cose, err := a.coseKey()
		if err != nil {
			return nil, err
		}
		out = append(out, cose...)
	}
	return out, nil
}

// CreateResponse answers a registration ceremony: the JSON body the
// browser would POST after navigator.credentials.create.
func (a *Authenticator) CreateResponse(creationOptionsJSON []byte) ([]byte, error) {
	var opts publicKeyOptions
	if err := json.Unmarshal(creationOptionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("authtest: options: %w", err)
	}
	if uid, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID); err == nil {
		a.UserID = uid
	}
	// Flags 0x45: user present + user verified + attested data.
	authData, err := a.authData(0x45, true)
	if err != nil {
		return nil, err
	}
	attObj, err := cbor.Marshal(struct {
		AuthData []byte         `cbor:"authData"`
		Fmt      string         `cbor:"fmt"`
		AttStmt  map[string]any `cbor:"attStmt"`
	}{AuthData: authData, Fmt: "none", AttStmt: map[string]any{}})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64u(a.CredID), "rawId": b64u(a.CredID), "type": "public-key",
		"response": map[string]any{
			"attestationObject": b64u(attObj),
			"clientDataJSON":    b64u(clientData("webauthn.create", opts.PublicKey.Challenge, a.Origin)),
		},
	})
}

// GetResponse answers a login ceremony: the JSON body the browser
// would POST after navigator.credentials.get.
func (a *Authenticator) GetResponse(assertionOptionsJSON []byte) ([]byte, error) {
	var opts publicKeyOptions
	if err := json.Unmarshal(assertionOptionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("authtest: options: %w", err)
	}
	a.Counter++
	// Flags 0x05: user present + user verified.
	authData, err := a.authData(0x05, false)
	if err != nil {
		return nil, err
	}
	cdj := clientData("webauthn.get", opts.PublicKey.Challenge, a.Origin)
	cdjHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(authData, cdjHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64u(a.CredID), "rawId": b64u(a.CredID), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": b64u(authData),
			"clientDataJSON":    b64u(cdj),
			"signature":         b64u(sig),
			"userHandle":        b64u(a.UserID),
		},
	})
}
