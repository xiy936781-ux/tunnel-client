//go:build !linux

package localfiles

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Non-Linux tests exercise the fail-closed stub: every scenario must return
// ErrCredentialNotSupported without touching the filesystem beyond setup.

func TestOpenCredentialOtherPlatformFailsClosed(t *testing.T) {
	dir := makeTempRoot(t)
	credPath := filepath.Join(dir, "token")
	if err := os.WriteFile(credPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	_, err = OpenCredential(root, "token")
	if err != ErrCredentialNotSupported {
		t.Fatalf("expected ErrCredentialNotSupported, got: %v", err)
	}
}

// Scenario matrix on non-Linux: every case fails closed with the same error,
// even when the on-disk precondition would be satisfiable on Linux.

func TestOpenCredentialOtherPlatformRejectsAllCases(t *testing.T) {
	dir := makeTempRoot(t)
	_ = os.Chmod(dir, 0o700) // root itself is fine
	credPath := filepath.Join(dir, "cred")
	_ = os.WriteFile(credPath, []byte("x"), 0o600)

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	for _, name := range []string{"cred", "../escape", ".", "..", "a/b", "no-such"} {
		if _, err := OpenCredential(root, name); err != ErrCredentialNotSupported {
			t.Errorf("name %q: expected ErrCredentialNotSupported, got: %v", name, err)
		}
	}
}

// makeTempRoot creates a 0700 temp directory owned by the current uid.
func makeTempRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "credtest")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return dir
}

var _ = syscall.ENOSYS
