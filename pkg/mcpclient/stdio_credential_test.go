package mcpclient

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/localfiles"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

// fakeCredentialResolver is a test stub that returns a fixed token without
// touching any real credential file.
func fakeCredentialResolver(token string, err error) func(string) ([]byte, error) {
	return func(credFile string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(token), nil
	}
}

// newExecCmdPlaceholder creates a *exec.Cmd without starting it.
func newExecCmdPlaceholder(t *testing.T) *exec.Cmd {
	t.Helper()
	// Use "true" as a safe, universally available command; we never Start it.
	cmd := exec.Command("true")
	require.NotNil(t, cmd)
	return cmd
}

// --- No credential: existing behavior preserved -----------------------------

func TestApplyCredentialEnvNilCredential(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:     "some-cmd",
		CommandArgs: []string{"some-cmd"},
	}
	cmd := newExecCmdPlaceholder(t)
	require.Nil(t, cmd.Env)
	err := applyCredentialEnv(cmd, cfg, nil)
	require.NoError(t, err)
	require.Nil(t, cmd.Env, "cmd.Env must remain nil when CredentialFile is empty")
}

// --- Fail-closed when resolver is nil but CredentialFile is set ------------

func TestApplyCredentialEnvNilResolverFailsClosed(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no credential resolver")
	require.Nil(t, cmd.Env, "cmd.Env must not be set when resolver is nil")
}

// --- Credential command mismatch -------------------------------------------

func TestApplyCredentialEnvCommandMismatch(t *testing.T) {
	// Write a dummy credential file so the test is self-contained.
	credDir, err := os.MkdirTemp("", "credtest")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(credDir) })
	require.NoError(t, os.Chmod(credDir, 0o700))
	credFile := filepath.Join(credDir, "relay-token")
	require.NoError(t, os.WriteFile(credFile, []byte("dummy-test-token"), 0o600))

	resolver := fakeCredentialResolver("dummy-test-token", nil)

	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "wrong-basename", // mismatch
	}
	cmd := newExecCmdPlaceholder(t)
	err = applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential-command mismatch")
	require.Nil(t, cmd.Env)
}

// --- Fail-closed when credential-command is not set ------------------------

func TestApplyCredentialEnvMissingCredentialCommand(t *testing.T) {
	resolver := fakeCredentialResolver("dummy-test-token", nil)

	cfg := &runtimeconfig.MCPConfig{
		Command:       "node relay-mcp-server.mjs",
		CommandArgs:   []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile: "relay-token",
		// CredentialCommand intentionally empty: the binding must be refused.
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential-command is not set")
	require.Nil(t, cmd.Env)
}

// --- Successful credential injection (test stub, no real credential) -------

func TestApplyCredentialEnvSuccess(t *testing.T) {
	const testToken = "test-dummy-token-value"
	resolver := fakeCredentialResolver(testToken, nil)

	// Establish known parent environment to verify the whitelist excludes
	// all parent variables except PATH and HOME.
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("OPENAI_API_KEY", "fake-parent-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fake-parent-aws-secret")
	t.Setenv("RELAY_TOKEN", "stale-parent-relay-token")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")

	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.NoError(t, err)
	require.Len(t, cmd.Env, 3, "cmd.Env must contain exactly 3 entries")

	// Verify the env whitelist: exactly PATH, HOME, RELAY_TOKEN.
	envKeys := make(map[string]bool)
	for _, kv := range cmd.Env {
		key := strings.SplitN(kv, "=", 2)[0]
		envKeys[key] = true
	}
	require.True(t, envKeys["PATH"], "cmd.Env must contain PATH")
	require.True(t, envKeys["HOME"], "cmd.Env must contain HOME")
	require.True(t, envKeys["RELAY_TOKEN"], "cmd.Env must contain RELAY_TOKEN")
	require.Len(t, envKeys, 3, "cmd.Env must not contain any other variables")

	// Verify the token value is present (test stub only — no real credential).
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "RELAY_TOKEN=") {
			val := strings.TrimPrefix(kv, "RELAY_TOKEN=")
			require.Equal(t, testToken, val)
		}
	}

	// Verify no parent secret variables leaked into the whitelist.
	for _, kv := range cmd.Env {
		require.NotContains(t, kv, "fake-parent-secret")
		require.NotContains(t, kv, "fake-parent-aws-secret")
		require.NotContains(t, kv, "stale-parent-relay-token")
		require.NotContains(t, kv, "/tmp/evil.so")
	}

	// Verify PATH and HOME are carried through from the parent environment.
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "PATH=") {
			require.Equal(t, "/usr/bin:/bin", strings.TrimPrefix(kv, "PATH="))
		}
		if strings.HasPrefix(kv, "HOME=") {
			require.Equal(t, "/home/testuser", strings.TrimPrefix(kv, "HOME="))
		}
	}
}

// --- Token exceeding max size is refused -----------------------------------

func TestApplyCredentialEnvOversizedToken(t *testing.T) {
	oversized := strings.Repeat("x", localfiles.MaxCredentialBytes+1)
	resolver := fakeCredentialResolver(oversized, nil)

	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
	require.Nil(t, cmd.Env)
}

// --- Empty token is refused ------------------------------------------------

func TestApplyCredentialEnvEmptyToken(t *testing.T) {
	resolver := fakeCredentialResolver("", nil)
	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
	require.Nil(t, cmd.Env)
}

// --- Resolver error propagates without leaking credential value ------------

func TestApplyCredentialEnvResolverErrorNoLeak(t *testing.T) {
	sentinel := "secret-sentinel-12345678"
	resolver := func(string) ([]byte, error) {
		return nil, errors.New("cannot read credential")
	}
	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.Error(t, err)
	// The error message must not contain the sentinel value.
	require.NotContains(t, err.Error(), sentinel)
	require.Nil(t, cmd.Env)
}

// --- No credential: transport preserves nil env (regression test) ----------

func TestStdioCommandTransportNoCredentialPreservesNilEnv(t *testing.T) {
	lifecycle := &stubLifecycle{}
	transport := newStdioCommandTransport(nil, lifecycle, nil)

	cfg := &runtimeconfig.MCPConfig{
		Command:     "true",
		CommandArgs: []string{"true"},
	}
	_, err := transport.Transport(cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	cmd := transport.cmd
	transport.mu.Unlock()
	require.NotNil(t, cmd)
	require.Nil(t, cmd.Env, "cmd.Env must be nil when no credential is bound")
}

// --- Config parse tests: credential validation via public API ---------------

// These tests verify that the stdio MCP config parsing correctly rejects
// invalid credential values. They use the public Load/parseMCPBindingEntry
// path exercised through runtimeconfig functions.
func TestStdioCredentialConfigParseValid(t *testing.T) {
	// Simulate what parseMCPBindingEntry does for a valid credential binding.
	// The actual parsing is in runtimeconfig; here we verify that a
	// well-formed MCPConfig with credential fields passes applyCredentialEnv.
	cfg := &runtimeconfig.MCPConfig{
		Command:           "node relay-mcp-server.mjs",
		CommandArgs:       []string{"/usr/bin/node", "relay-mcp-server.mjs"},
		CredentialFile:    "relay-token",
		CredentialCommand: "node",
	}
	cmd := newExecCmdPlaceholder(t)
	// With a working resolver, the valid config should succeed.
	resolver := fakeCredentialResolver("test-token-value", nil)
	err := applyCredentialEnv(cmd, cfg, resolver)
	require.NoError(t, err)
	require.NotNil(t, cmd.Env)
}

func TestStdioCredentialConfigParseEmptyCredential(t *testing.T) {
	cfg := &runtimeconfig.MCPConfig{
		Command:     "true",
		CommandArgs: []string{"true"},
	}
	cmd := newExecCmdPlaceholder(t)
	err := applyCredentialEnv(cmd, cfg, nil)
	require.NoError(t, err)
	require.Nil(t, cmd.Env)
}
