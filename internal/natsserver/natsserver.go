// Package natsserver runs the embedded JetStream server the standalone
// fold stores itself on (roadmap M1: "an embedded nats-server as the
// store"). Embedded deployments skip this package entirely and hand the
// store a connection to their own server.
package natsserver

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

// Start runs a loopback JetStream server on storeDir and returns it
// once it accepts connections.
func Start(storeDir string) (*server.Server, error) {
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  storeDir,
		NoLog:     true,
		NoSigs:    true,
	}
	s, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("natsserver: %w", err)
	}
	s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		s.Shutdown()
		return nil, errors.New("natsserver: not ready within 10s")
	}
	return s, nil
}
