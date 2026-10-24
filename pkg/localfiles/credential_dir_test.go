//go:build !linux

package localfiles

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Non-Linux tests exercise the fail-closed stub: every scenario must return
// ErrCredentialNotSupported without touching the filesystem beyond setup.

func TestEnsureCredentialDirOtherPlatformFailsClosed(t *testing.T) {
	dir := makeTempRoot(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	// Even when the on-disk precondition (a 0700 credentials dir) would be
	// satisfiable on Linux, the non-Linux path must fail closed.
	credDir := filepath.Join(dir, "credentials")
	_ = os.MkdirAll(credDir, 0o700)

	if _, err := EnsureCredentialDir(root, "credentials"); !errors.Is(err, ErrCredentialNotSupported) {
		t.Fatalf("expected ErrCredentialNotSupported, got: %v", err)
	}
}

// Scenario matrix on non-Linux: every case fails closed with the same error.
func TestEnsureCredentialDirOtherPlatformRejectsAllCases(t *testing.T) {
	dir := makeTempRoot(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	for _, name := range []string{"credentials", "../escape", ".", "..", "a/b", ""} {
		if _, err := EnsureCredentialDir(root, name); !errors.Is(err, ErrCredentialNotSupported) {
			t.Errorf("name %q: expected ErrCredentialNotSupported, got: %v", name, err)
		}
	}
}

// Nil root must also fail closed on all platforms.
func TestEnsureCredentialDirNilRootOtherPlatform(t *testing.T) {
	if _, err := EnsureCredentialDir(nil, "credentials"); !errors.Is(err, ErrCredentialNotSupported) {
		t.Fatalf("expected ErrCredentialNotSupported for nil root on non-linux, got: %v", err)
	}
}
