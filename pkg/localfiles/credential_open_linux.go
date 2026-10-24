//go:build linux

package localfiles

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openCredentialLinux implements the platform-specific credential open for
// Linux using openat2(2) with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS.
//
// The single-component credential name is resolved strictly within the
// already-verified directory handle in one syscall; the kernel refuses any
// symlink component, closing the Lstat→Open window on the file entry itself.
// The directory handle's own provenance (verified by verifyCredentialRoot) is
// the remaining precondition; it is the caller's responsibility to hold the
// verified handle across the call, which is why OpenCredential requires an
// *os.Root rather than a path string.
//
// Fail-closed: if the kernel does not support openat2 (ENOSYS) or rejects the
// resolve flags (EPERM/EINVAL/EPROTONOSUPPORT), the error is returned to the
// caller and no fallback is attempted.
func openCredentialLinux(rootDir *os.Root, credentialFile string, rootInfo os.FileInfo) (io.ReadCloser, error) {
	name, err := singleComponentName(credentialFile)
	if err != nil {
		return nil, err
	}

	// os.Root.Open(".") returns an *os.File bound to the same directory
	// handle; its Fd() is the raw directory fd openat2 requires.
	dirFile, err := rootDir.Open(".")
	if err != nil {
		return nil, fmt.Errorf("localfiles: credential root handle: %w", err)
	}
	defer func() { _ = dirFile.Close() }()

	// Verify that the directory we just opened is the same inode that
	// verifyCredentialRoot validated. os.Root holds a fixed dirfd, so
	// both rootDir.Stat(".") and rootDir.Open(".") resolve through that
	// fd; SameFile on the two handles closes the window where the directory
	// could have been unlinked and recreated between the two calls.
	dirOpenedInfo, err := dirFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialRootInvalid, err)
	}
	if !os.SameFile(dirOpenedInfo, rootInfo) {
		return nil, fmt.Errorf("%w: directory inode changed between validation and open", ErrCredentialRootInvalid)
	}

	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Mode:    0,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(int(dirFile.Fd()), name, how)
	if err != nil {
		// Only ENOSYS and EPROTONOSUPPORT have reliable evidence that the
		// kernel or system does not support openat2 / the resolve flags.
		// EPERM may indicate a capability restriction (container, seccomp)
		// rather than missing kernel support; EINVAL may indicate a
		// malformed OpenHow or wrong fd type. Both must be reported as
		// operational failures, NOT as "platform not supported", so the
		// caller can distinguish and act accordingly.
		switch {
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPROTONOSUPPORT):
			return nil, fmt.Errorf("localfiles: openat2 unavailable on this kernel; credential open refused: %w", ErrCredentialNotSupported)
		case errors.Is(err, unix.EPERM):
			return nil, fmt.Errorf("localfiles: openat2 permission denied (capability or seccomp restriction): %w", err)
		case errors.Is(err, unix.EINVAL):
			return nil, fmt.Errorf("localfiles: openat2 invalid argument (bad fd or OpenHow): %w", err)
		default:
			return nil, fmt.Errorf("localfiles: openat2 credential open: %w", err)
		}
	}

	file := os.NewFile(uintptr(fd), name)
	if verifyErr := verifyCredentialFile(file); verifyErr != nil {
		return nil, verifyErr
	}
	return file, nil
}
