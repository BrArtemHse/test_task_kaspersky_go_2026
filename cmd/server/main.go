// Command server runs the threat exchange HTTP service.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat-exchange/internal/config"
	"threat-exchange/internal/httpapi"
	"threat-exchange/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	db, err := store.Open(startup, cfg.DBPath)
	cancelStartup()
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("close database", "error", err)
		}
	}()
	handler, err := httpapi.New(db, httpapi.Options{Token: cfg.Token, RPS: cfg.RPS, Burst: cfg.Burst, Logger: logger})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: cfg.Address, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer func() { _ = srv.Close() }()
	result := make(chan error, 1)
	go func() {
		if cfg.TLSCert != "" {
			result <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			return
		}
		result <- srv.ListenAndServe()
	}()
	logger.Info("starting HTTP server", "address", cfg.Address, "tls", cfg.TLSCert != "")
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		stop()
		logger.Info("shutting down HTTP server")
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return fmt.Errorf("shutdown HTTP: %w", err)
		}
		if err := <-result; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	}
}
