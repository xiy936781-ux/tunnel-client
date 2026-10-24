// Package localfiles credential-open layer: independent, read-only, fail-closed
// credential file access.
//
// It is intentionally NOT wired into config parsing or MCP transport startup;
// it is a standalone layer that future callers must use through
// OpenCredential. Every security check that can fail will refuse to open the
// credential; there is no degraded / best-effort path.
package localfiles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
)

// ErrCredentialNotSupported is returned on platforms where no fail-closed,
// symlink-safe credential open can be provided. Callers MUST treat it as a
// hard refusal and MUST NOT fall back to os.ReadFile or any other path.
var ErrCredentialNotSupported = errors.New("localfiles: secure credential open is not supported on this platform; credential binding refused")

// ErrCredentialRootInvalid is returned when the trusted root directory handle
// cannot be verified as a 0700 directory owned by the current uid.
var ErrCredentialRootInvalid = errors.New("localfiles: credential root is not a verified 0700 directory owned by the current user")

// OpenCredential verifies that rootDir (an already-opened directory, e.g. the
// trusted state root) is a regular directory with mode 0700 owned by the
// current effective uid, then opens the single basename credentialFile
// read-only with the platform's strongest available guarantee:
//
//   - Linux: openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS so that
//     resolution cannot escape the directory and no path component is a
//     symlink; the kernel rejects anything that is not a plain entry.
//   - Any other GOOS: the operation fails closed with
//     ErrCredentialNotSupported. This is deliberate: Lstat→Open→fstat cannot
//     be presented as a race-free substitute, so on unsupported platforms
//     the credential layer simply refuses to operate rather than degrading.
//
// The credential file must be a regular file owned by the current effective
// uid with mode exactly 0600. Symbolic links, FIFOs, character and block
// devices, and path traversal components are all refused.
func OpenCredential(rootDir *os.Root, credentialFile string) (io.ReadCloser, error) {
	if rootDir == nil {
		return nil, errors.New("localfiles: root directory handle is required for credential open")
	}
	// Fail closed on unsupported platforms before doing any file work.
	if runtime.GOOS != "linux" {
		return nil, ErrCredentialNotSupported
	}
	rootInfo, err := verifyCredentialRoot(rootDir)
	if err != nil {
		return nil, err
	}
	return openCredentialLinux(rootDir, credentialFile, rootInfo)
}

// verifyCredentialRoot enforces the trusted-root preconditions:
//   - rootDir must be a directory;
//   - mode must be exactly 0700;
//   - owning uid must equal the current effective uid.
//
// This check runs against the open handle (fstat semantics via
// rootDir.Stat(".")), not against the path string, so the path is not
// re-resolved and cannot be swapped out between validation and use.
func verifyCredentialRoot(rootDir *os.Root) (os.FileInfo, error) {
	info, err := rootDir.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialRootInvalid, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: root is not a directory", ErrCredentialRootInvalid)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o700); got != want {
		return nil, fmt.Errorf("%w: root mode is %03o, want 0700", ErrCredentialRootInvalid, got)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Geteuid() {
			return nil, fmt.Errorf("%w: root owned by uid %d, want %d", ErrCredentialRootInvalid, stat.Uid, os.Geteuid())
		}
	} else {
		// If the platform's sysinfo does not expose the expected struct we
		// cannot verify ownership; fail closed rather than guessing.
		return nil, fmt.Errorf("%w: unable to determine root owner", ErrCredentialRootInvalid)
	}
	return info, nil
}

// singleComponentName validates that credentialFile is a single, plain
// basename: no separators, not "." or "..", no leading dot-run that could
// hide a path component.
func singleComponentName(name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("localfiles: credential file name must be a single basename, got %q", name)
	}
	if anyByte(name, isPathSeparatorByte) {
		return "", fmt.Errorf("localfiles: credential file name %q must not contain path separators", name)
	}
	if anyByte(name, isDotByte) {
		// "." and ".." already rejected above; any other dot is allowed in a
		// real file name (e.g. "token.json").
	}
	return name, nil
}

func isPathSeparatorByte(b byte) bool { return b == '/' || b == byte(os.PathSeparator) }
func isDotByte(b byte)                bool { return b == '.' }
func anyByte(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if f(s[i]) {
			return true
		}
	}
	return false
}

// verifyCredentialFile enforces, on the open file handle:
//   - regular file (rejects FIFO, character and block devices);
//   - mode exactly 0600;
//   - owning uid equals the current effective uid.
//
// Any failure refuses the credential; there is no partial success.
func verifyCredentialFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("localfiles: credential file stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("localfiles: credential file must be a regular file, got %s", info.Mode().Type().String())
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		_ = file.Close()
		return fmt.Errorf("localfiles: credential file mode is %03o, want 0600", got)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Geteuid() {
			_ = file.Close()
			return fmt.Errorf("localfiles: credential file owned by uid %d, want %d", stat.Uid, os.Geteuid())
		}
	} else {
		_ = file.Close()
		return errors.New("localfiles: unable to determine credential file owner; refusing to open")
	}
	return nil
}
