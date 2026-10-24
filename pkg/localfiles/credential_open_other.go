//go:build !linux

package localfiles

import (
	"io"

	"os"
)

// openCredentialOther implements the platform-specific credential open for
// every non-Linux GOOS.
//
// It is a fail-closed stub: it always returns ErrCredentialNotSupported and
// performs no file access. This is intentional. An Lstat→Open→fstat
// sequence cannot be presented as a race-free substitute for the Linux
// openat2 guarantee, and the security policy for this layer is that any
// credential open which cannot be verified to be symlink-safe and atomic
// must refuse to run rather than degrade.
//
// If a future non-Linux platform provides an equivalent atomic mechanism, it
// should implement openCredentialOther for that GOOS with its own build tag
// before calling OpenCredential is considered supported there.
func openCredentialLinux(rootDir *os.Root, credentialFile string, rootInfo os.FileInfo) (io.ReadCloser, error) {
	_ = rootDir
	_ = credentialFile
	_ = rootInfo
	return nil, ErrCredentialNotSupported
}
