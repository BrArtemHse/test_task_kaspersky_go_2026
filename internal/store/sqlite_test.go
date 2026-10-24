package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"threat-exchange/internal/threat"
)

func TestPersistenceAndReplacement(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "threats.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.Create(ctx, threat.Threat{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Old", Severity: "high", Category: "trojan", Description: "old"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.Update(ctx, threat.Threat{MD5: item.MD5, Name: "New", Severity: "unknown", Category: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Description != "" || updated.Name != "New" || !updated.CreatedAt.Equal(item.CreatedAt) || updated.UpdatedAt.Before(item.UpdatedAt) {
		t.Fatalf("replacement: %+v", updated)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.Get(ctx, item.MD5)
	if err != nil || got.Name != "New" {
		t.Fatalf("persistence: %+v, %v", got, err)
	}
	_, err = s.Get(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing get: %v", err)
	}
	_, err = s.Update(ctx, threat.Threat{MD5: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "Missing", Severity: "unknown", Category: "unknown"})
	if !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing update: %v", err)
	}
}

func TestConcurrentCreate(t *testing.T) {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "threats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Create(context.Background(), threat.Threat{MD5: "d41d8cd98f00b204e9800998ecf8427e", Name: "Trojan", Category: "unknown", Severity: "unknown"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, threat.ErrConflict) {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("created %d records; want 1", created)
	}
}
