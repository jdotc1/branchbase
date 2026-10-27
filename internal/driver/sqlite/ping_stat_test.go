package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPingPropagatesStatError(t *testing.T) {
	base := filepath.Join(t.TempDir(), "loop.db")
	if err := os.Symlink(base, base); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	drv, err := New(Config{BasePath: base})
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(base)
	if statErr == nil || os.IsNotExist(statErr) {
		t.Fatalf("fixture must produce a non-not-exist stat error: %v", statErr)
	}
	err = drv.Ping(context.Background())
	var pathErr *os.PathError
	if !errors.As(statErr, &pathErr) || !errors.Is(err, pathErr.Err) {
		t.Fatalf("Ping must preserve the stat error %v; got %v", statErr, err)
	}
}
