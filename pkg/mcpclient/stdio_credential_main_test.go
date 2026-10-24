package mcpclient

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/localfiles"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

// newCredentialTransportForTest constructs a stdioCommandTransport the same
// way the production fx module does: observation nil, credentialResolver
// nil. Tests that call transport.Transport with this instance exercise the
// exact production wiring path and must NOT inject a stub resolver.
func newCredentialTransportForTest() *stdioCommandTransport {
	return newStdioCommandTransport(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&stubLifecycle{},
		nil,
	)
}

// --- Main channel projection: credential fields must be carried through ----

// TestMainProjectionPreservesCredentialBinding verifies that a projected
// main-channel stdio binding that carries a credential is refused
// fail-closed when no resolver is wired (the production state). This
// guards the regression where buildMCPConfig dropped CredentialFile /
// CredentialCommand from the main projection, silently skipping the
// injection guard for legacy callers that read cfg.CommandArgs.
func TestMainProjectionPreservesCredentialBinding(t *testing.T) {
	// Simulate the production main-binding projection with credentials:
	// the cfg-level CredentialFile/CredentialCommand come from the main
	// binding via buildMCPConfig.
	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}

	// With a nil resolver (production wiring), the transport must refuse
	// the child process fail-closed; it must not silently start the child
	// with the inherited parent environment (which would defeat the
	// credential whitelist).
	transport := newCredentialTransportForTest()
	_, err := transport.Transport(cfg)
	require.Error(t, err, "credential-bound stdio with nil resolver must fail-closed")
	require.Contains(t, err.Error(), "no credential resolver")
}

// TestMainProjectionCredentialMismatchRefused verifies that a projected
// main-channel binding whose executable basename does not match the
// declared CredentialCommand is refused even with a working resolver.
func TestMainProjectionCredentialMismatchRefused(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:           "bash some-script.sh",
		CommandArgs:       []string{"bash", "some-script.sh"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node", // mismatch: actual basename is "bash"
	}
	cmd := newExecCmdPlaceholder(t)
	resolver := fakeCredentialResolver("dummy-test-token", nil)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential-command mismatch")
	require.Nil(t, cmd.Env)
}

// TestMainProjectionCredentialMissingCommandRefused verifies that a
// projected main-channel binding with a CredentialFile but no
// CredentialCommand is refused (fail-closed contract: a binding that
// does not declare the expected executable identity cannot pass the
// cross-check).
func TestMainProjectionCredentialMissingCommandRefused(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:        "node relay-mcp-server.mjs",
		CommandArgs:    []string{"node", "relay-mcp-server.mjs"},
		CredentialFile: "relay-token",
		// CredentialCommand intentionally empty.
	}
	cmd := newExecCmdPlaceholder(t)
	resolver := fakeCredentialResolver("dummy-test-token", nil)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential-command is not set")
	require.Nil(t, cmd.Env)
}

// TestMainProjectionNoCredentialInheritsParentEnv verifies that a stdio
// main-channel binding with no credential file keeps the legacy behavior:
// cmd.Env stays nil so the child inherits the full parent environment.
func TestMainProjectionNoCredentialInheritsParentEnv(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:     "true",
		CommandArgs: []string{"true"},
	}
	cmd := newExecCmdPlaceholder(t)
	require.NoError(t, applyCredentialEnv(cmd, cfg, nil))
	require.Nil(t, cmd.Env, "no credential bound: cmd.Env must stay nil so child inherits parent env")
}

// --- Bounded-read constant --------------------------------------------------

// TestMaxCredentialBytesIsPositive documents the bounded-read constant so
// the ceiling is pinned in the mcpclient package where it is enforced.
func TestMaxCredentialBytesIsPositive(t *testing.T) {
	require.Greater(t, localfiles.MaxCredentialBytes, 0)
	require.Equal(t, 4096, localfiles.MaxCredentialBytes)
}
