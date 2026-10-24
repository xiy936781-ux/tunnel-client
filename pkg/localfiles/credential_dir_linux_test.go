//go:build linux

package localfiles

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// --- Positive cases -------------------------------------------------------

func TestEnsureCredentialDirCreatesNew(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	root := openRoot(t, dir)

	child, err := EnsureCredentialDir(root, "credentials")
	if err != nil {
		t.Fatalf("EnsureCredentialDir: %v", err)
	}
	defer func() { _ = child.Close() }()

	// Confirm the directory was created 0700.
	info, err := child.Stat(".")
	if err != nil {
		t.Fatalf("child.Stat: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o700); got != want {
		t.Fatalf("created credential dir mode = %03o, want 0700", got)
	}
}

func TestEnsureCredentialDirReusesExisting0700(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	credDir := filepath.Join(dir, "credentials")
	if err := os.MkdirAll(credDir, 0o700); err != nil {
		t.Fatalf("setup MkdirAll: %v", err)
	}
	root := openRoot(t, dir)

	child, err := EnsureCredentialDir(root, "credentials")
	if err != nil {
		t.Fatalf("EnsureCredentialDir: %v", err)
	}
	defer func() { _ = child.Close() }()
}

// --- Negative cases -------------------------------------------------------

func TestEnsureCredentialDirRejects0755(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	credDir := filepath.Join(dir, "credentials")
	if err := os.MkdirAll(credDir, 0o755); err != nil {
		t.Fatalf("setup MkdirAll: %v", err)
	}
	root := openRoot(t, dir)

	if _, err := EnsureCredentialDir(root, "credentials"); err == nil {
		t.Fatal("expected error for pre-existing 0755 credential dir, got nil")
	}
	// Confirm the dir was NOT auto-chmod'd: it must still be 0755.
	info, err := os.Stat(credDir)
	if err != nil {
		t.Fatalf("Stat after rejection: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("pre-existing dir was modified to %03o; must remain 0755 (no auto-chmod)", got)
	}
}

func TestEnsureCredentialDirRejectsWrongOwner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	credDir := filepath.Join(dir, "credentials")
	if err := os.MkdirAll(credDir, 0o700); err != nil {
		t.Fatalf("setup MkdirAll: %v", err)
	}
	// Chown to a different uid; requires root. Pick uid 1 (daemon), or 0
	// if we are running as root.
	uid := 1
	if os.Geteuid() == 1 {
		uid = 0
	}
	if err := unix.Chown(credDir, uid, -1); err != nil {
		t.Skipf("cannot chown (not running as root): %v", err)
	}
	root := openRoot(t, dir)

	if _, err := EnsureCredentialDir(root, "credentials"); err == nil {
		t.Fatal("expected error for non-owner credential dir, got nil")
	}
}

func TestEnsureCredentialDirRejectsSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	// Target dir outside root.
	target := makeTempRoot(t)
	_ = target // keep alive for cleanup
	_ = os.Chmod(target, 0o700)
	_ = target

	// Symlink inside root pointing to the target.
	sym := filepath.Join(dir, "credentials")
	if err := os.Symlink(target, sym); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	root := openRoot(t, dir)

	if _, err := EnsureCredentialDir(root, "credentials"); err == nil {
		t.Fatal("expected error for symlink credential dir, got nil")
	}
}

func TestEnsureCredentialDirRejectsFIFO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	fifo := filepath.Join(dir, "credentials")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	root := openRoot(t, dir)

	if _, err := EnsureCredentialDir(root, "credentials"); err == nil {
		t.Fatal("expected error for FIFO credential dir, got nil")
	}
}

// --- Parent root failures -------------------------------------------------

func TestEnsureCredentialDirRejectsUnsafeParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	// Make the root itself 0755: verifyCredentialRoot must reject before
	// any subdirectory work happens.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	root := openRoot(t, dir)

	if _, err := EnsureCredentialDir(root, "credentials"); err == nil {
		t.Fatal("expected error for 0755 parent root, got nil")
	}
}

// --- Name validation ------------------------------------------------------

func TestEnsureCredentialDirRejectsBadNames(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("EnsureCredentialDir is fail-closed on %s", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	root := openRoot(t, dir)

	for _, name := range []string{"", ".", "..", "a/b", "../x", "x/../y"} {
		if _, err := EnsureCredentialDir(root, name); err == nil {
			t.Errorf("name %q: expected error, got nil", name)
		}
	}
}

// --- Nil root -------------------------------------------------------------

func TestEnsureCredentialDirNilRoot(t *testing.T) {
	if _, err := EnsureCredentialDir(nil, "credentials"); err == nil {
		t.Fatal("expected error for nil root, got nil")
	}
}

// --- End-to-end with OpenCredential ---------------------------------------

func TestEnsureCredentialDirThenOpenCredential(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("openat2 path only on linux; %s is fail-closed", runtime.GOOS)
	}
	dir := makeTempRoot(t)
	root := openRoot(t, dir)

	credDir, err := EnsureCredentialDir(root, "credentials")
	if err != nil {
		t.Fatalf("EnsureCredentialDir: %v", err)
	}
	defer func() { _ = credDir.Close() }()

	// Write a 0600 credential file inside the created dir.
	if err := credDir.WriteFile("token", []byte("dummy-value"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rc, err := OpenCredential(credDir, "token")
	if err != nil {
		t.Fatalf("OpenCredential: %v", err)
	}
	defer func() { _ = rc.Close() }()
}
