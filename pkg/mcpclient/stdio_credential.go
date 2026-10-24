package mcpclient

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/openai/tunnel-client/pkg/localfiles"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

// applyCredentialEnv builds the cmd.Env whitelist for a credential-bound
// stdio binding. All failures are returned to the caller and must result in
// the transport construction failing before the child process is started.
//
// The env whitelist contains exactly:
//   - PATH (from the parent environment)
//   - HOME (from the parent environment)
//   - RELAY_TOKEN (read from the credential file via credentialResolver)
//
// The credential value is NEVER logged, NEVER written to a file, and NEVER
// placed on the command line. It exists only in the in-memory []string
// passed to execve — the L1 minimum. This is NOT L2.
//
// credentialResolver is the injected function that performs the full
// security chain (trusted root verification, atomic open, bounded read).
// When it is nil, credential injection is refused fail-closed.
func applyCredentialEnv(
	cmd *exec.Cmd,
	cfg *runtimeconfig.MCPConfig,
	credentialResolver func(credentialFile string) ([]byte, error),
) error {
	if cfg.CredentialFile == "" {
		return nil // no credential bound; cmd.Env stays nil (existing behavior)
	}

	// 1. Executable identity cross-check. The expected executable basename
	// must be explicitly declared and must match the command's actual basename.
	// A binding that omits CredentialCommand cannot pass the identity check
	// and is refused fail-closed.
	actualBasename := filepath.Base(cfg.CommandArgs[0])
	if cfg.CredentialCommand == "" {
		return errors.New(
			"mcpclient: credential file is bound but credential-command is not set; " +
				"refusing credential injection",
		)
	}
	if actualBasename != cfg.CredentialCommand {
		return fmt.Errorf(
			"mcpclient: credential-command mismatch: expected %q but command resolves to %q; refusing credential injection",
			cfg.CredentialCommand, actualBasename,
		)
	}

	// 2. Fail-closed when no resolver is wired.
	if credentialResolver == nil {
		return errors.New(
			"mcpclient: credential file is bound but no credential resolver is available " +
				"(trusted executable baseline not yet wired); refusing to start child process",
		)
	}

	// 3. Resolve the credential.
	tokenBytes, err := credentialResolver(cfg.CredentialFile)
	if err != nil {
		// Never include the credential basename or value in the error.
		return fmt.Errorf("mcpclient: credential resolution failed: %w", err)
	}
	if len(tokenBytes) == 0 {
		return errors.New("mcpclient: credential resolved to empty value; refusing")
	}
	if len(tokenBytes) > localfiles.MaxCredentialBytes {
		return fmt.Errorf("mcpclient: credential exceeds %d bytes; refusing", localfiles.MaxCredentialBytes)
	}

	// 4. Build the minimal env whitelist.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"RELAY_TOKEN=" + string(tokenBytes),
	}
	return nil
}
