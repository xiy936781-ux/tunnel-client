// Package localfiles credential-open layer: independent, read-only, fail-closed
// credential directory management.
//
// EnsureCredentialDir provides the missing "create or verify a 0700 credentials
// subdirectory inside a verified trusted root" primitive that OpenCredential
// requires but does not itself provide. It is intentionally NOT wired into
// config parsing or MCP transport startup.
package localfiles

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// EnsureCredentialDir ensures that a single-basename subdirectory (e.g.
// "credentials") exists under rootDir with the security properties required
// to serve as the trusted root for OpenCredential:
//
//   - rootDir itself must already be a verified 0700 directory owned by the
//     current uid (verified via verifyCredentialRoot on the open handle);
//   - the subdirectory entry must NOT be a symlink, FIFO, or any non-directory
//     object (checked via Lstat before OpenRoot, mirroring the
//     managed_files.go L49-L58 pattern);
//   - if the subdirectory does not exist, it is created with mode 0700;
//   - if it already exists, its on-disk mode must be exactly 0700 and its
//     owning uid must equal the current uid; a 0755 (or any other mode) or
//     non-owner directory is refused and is NEVER auto-chmod'd — the caller
//     is expected to fix the pre-existing directory out-of-band;
//   - after opening the subdirectory handle, os.SameFile is used to confirm
//     the handle points to the same inode that was Lstat'ed, closing the
//     Lstat→Open window under the 0700 ownership invariant.
//
// The returned *os.Root is the open subdirectory handle; the caller is
// responsible for calling Close on it.
func EnsureCredentialDir(rootDir *os.Root, name string) (*os.Root, error) {
	if rootDir == nil {
		return nil, errors.New("localfiles: root directory handle is required for credential dir")
	}
	// Fail closed on unsupported platforms before doing any file work.
	if runtime.GOOS != "linux" {
		return nil, ErrCredentialNotSupported
	}

	// Verify the parent root handle itself.
	if _, err := verifyCredentialRoot(rootDir); err != nil {
		return nil, err
	}

	// Validate the single basename.
	clean, err := singleComponentName(name)
	if err != nil {
		return nil, fmt.Errorf("localfiles: credential dir name: %w", err)
	}

	// Lstat first, before opening, so a symlink/FIFO entry is refused before
	// any open follows it.
	lsInfo, lstatErr := rootDir.Lstat(clean)
	switch {
	case lstatErr == nil:
		// Entry exists; verify its type before opening.
		if mode := lsInfo.Mode(); mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: credential dir entry is a symlink", ErrCredentialRootInvalid)
		}
		if !lsInfo.IsDir() {
			return nil, fmt.Errorf("%w: credential dir entry is not a directory", ErrCredentialRootInvalid)
		}
		// Open the existing directory handle.
		child, err := rootDir.OpenRoot(clean)
		if err != nil {
			return nil, fmt.Errorf("localfiles: open existing credential dir: %w", err)
		}
		// Confirm the handle matches the inode we Lstat'ed (closes the
		// Lstat→Open window: if the entry was swapped between the two calls,
		// SameFile will differ and we refuse).
		childInfo, err := child.Stat(".")
		if err != nil {
			_ = child.Close()
			return nil, fmt.Errorf("%w: %v", ErrCredentialRootInvalid, err)
		}
		if !os.SameFile(childInfo, lsInfo) {
			_ = child.Close()
			return nil, fmt.Errorf("%w: credential dir inode changed between lstat and open", ErrCredentialRootInvalid)
		}
		// Verify 0700 + uid on the open handle.
		if err := verifyCredentialDirMode(child); err != nil {
			_ = child.Close()
			return nil, err
		}
		return child, nil
	case errors.Is(lstatErr, os.ErrNotExist):
		// Entry absent: create it 0700.
		if err := rootDir.Mkdir(clean, 0o700); err != nil {
			return nil, fmt.Errorf("localfiles: create credential dir: %w", err)
		}
		// Lstat the freshly created entry and open it, then confirm the open
		// handle matches the inode we just Lstat'ed. This closes the
		// Mkdir→Open window: if a same-uid attacker (0700 dir owner) swaps
		// the entry between Mkdir and OpenRoot, SameFile will differ and
		// we refuse.
		lsInfo2, err := rootDir.Lstat(clean)
		if err != nil {
			return nil, fmt.Errorf("localfiles: lstat newly created credential dir: %w", err)
		}
		if mode := lsInfo2.Mode(); mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: credential dir entry was replaced with a symlink after creation", ErrCredentialRootInvalid)
		}
		child, err := rootDir.OpenRoot(clean)
		if err != nil {
			return nil, fmt.Errorf("localfiles: open newly created credential dir: %w", err)
		}
		childInfo, err := child.Stat(".")
		if err != nil {
			_ = child.Close()
			return nil, fmt.Errorf("%w: %v", ErrCredentialRootInvalid, err)
		}
		if !os.SameFile(childInfo, lsInfo2) {
			_ = child.Close()
			return nil, fmt.Errorf("%w: credential dir inode changed between mkdir and open", ErrCredentialRootInvalid)
		}
		if err := verifyCredentialDirMode(child); err != nil {
			_ = child.Close()
			return nil, err
		}
		return child, nil
	default:
		// Any other Lstat error (EACCES, ELOOP, etc.): fail closed.
		return nil, fmt.Errorf("localfiles: lstat credential dir entry: %w", lstatErr)
	}
}

// verifyCredentialDirMode enforces, on the open directory handle:
//   - mode exactly 0700;
//   - owning uid equals the current effective uid.
//
// A pre-existing 0755 or non-owner directory is refused; it is never
// auto-chmod'd.
func verifyCredentialDirMode(dir *os.Root) error {
	info, err := dir.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialRootInvalid, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: credential dir handle is not a directory", ErrCredentialRootInvalid)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o700); got != want {
		return fmt.Errorf("%w: credential dir mode is %03o, want 0700 (pre-existing directories are not auto-chmod'd)", ErrCredentialRootInvalid, got)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Geteuid() {
			return fmt.Errorf("%w: credential dir owned by uid %d, want %d", ErrCredentialRootInvalid, stat.Uid, os.Geteuid())
		}
	} else {
		return fmt.Errorf("%w: unable to determine credential dir owner", ErrCredentialRootInvalid)
	}
	return nil
}
