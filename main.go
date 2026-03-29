package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/galang-rs/socks5/auth"
	"github.com/galang-rs/socks5/backend"
	"github.com/galang-rs/socks5/socks5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Multi-auth: same user can have multiple passwords
	authenticator := auth.New(
		auth.Credential("user1", "pass1"),
		auth.Credential("user1", "pass2"),
		auth.Credential("admin", "secret"),
	)

	// Start WireGuard backend
	be, err := backend.NewWireGuard(ctx, backend.WireGuardConfig{
		ConfigFile: "wireguard.conf",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer be.Close()

	// Start SOCKS5 proxy
	// LogLevelWarn  = only warnings and errors (production)
	// LogLevelInfo  = normal operational logs
	// LogLevelDebug = verbose packet-level tracing
	srv := socks5.New(
		socks5.WithAddr(":1080"),
		socks5.WithAuth(authenticator),
		socks5.WithBackend(be),
		socks5.WithLogLevel(socks5.LogLevelWarn),
	)

	log.Println("SOCKS5 proxy starting on :1080")
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatal(err)
	}
}
