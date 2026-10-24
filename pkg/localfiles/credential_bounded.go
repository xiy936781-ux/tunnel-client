package localfiles

import (
	"errors"
	"fmt"
	"io"
)

// MaxCredentialBytes is the hard upper bound on credential file size accepted
// by ReadCredentialBounded. A credential that exceeds this limit is refused;
// there is no degradation path.
const MaxCredentialBytes = 4096

// ReadCredentialBounded reads at most MaxCredentialBytes from rc and returns
// the content as a []byte. The caller MUST have obtained rc from
// OpenCredential; ReadCredentialBounded does not perform any security
// validation itself (that is OpenCredential's job) — it only enforces the
// size bound and clean handle management.
//
// Behaviour:
//   - rc is always Closed before return (success or failure), preventing fd
//     leaks even when the read itself errors.
//   - Empty content (0 bytes) is refused.
//   - Content longer than MaxCredentialBytes is refused (buffer is
//     MaxCredentialBytes+1 so an overlong read is detectable).
func ReadCredentialBounded(rc io.ReadCloser) ([]byte, error) {
	if rc == nil {
		return nil, errors.New("localfiles: credential reader is nil")
	}
	buf := make([]byte, MaxCredentialBytes+1)
	n, readErr := io.ReadFull(rc, buf)
	closeErr := rc.Close() // unconditional close; no fd leak on any path
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("localfiles: credential read: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("localfiles: credential close: %w", closeErr)
	}
	if n == 0 {
		return nil, errors.New("localfiles: credential file is empty; refusing")
	}
	if n > MaxCredentialBytes {
		return nil, fmt.Errorf("localfiles: credential file exceeds %d bytes; refusing", MaxCredentialBytes)
	}
	return buf[:n], nil
}
