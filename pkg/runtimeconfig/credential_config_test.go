package runtimeconfig

import (
	"testing"

	"github.com/spf13/pflag"

	"github.com/openai/tunnel-client/pkg/types"
)

// testCredentialLookupEnv returns a lookup that resolves only the keys in
// env. It mimics the minimal env needed for runtime flavor loads.
func testCredentialLookupEnv(t *testing.T, env map[string]string) func(string) (string, bool) {
	t.Helper()
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// newCredentialFlagSet builds a runtime-flavor flag set with the two args
// required for every runtime load plus any extra credential-related args.
// The control-plane API key is referenced via env:CONTROL_PLANE_API_KEY so
// the lookup resolves it without embedding a real key in the test args.
func newCredentialFlagSet(t *testing.T, extraArgs ...string) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("credential-test", pflag.ContinueOnError)
	RegisterFlags(fs, FlavorRuntime)
	args := []string{
		"--control-plane.tunnel-id", testTunnelID,
		"--control-plane.api-key", "env:CONTROL_PLANE_API_KEY",
	}
	args = append(args, extraArgs...)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return fs
}

// --- validateCredentialBasename ---------------------------------------------

func TestValidateCredentialBasename(t *testing.T) {
	t.Parallel()

	// Accept: plain basenames with dots and dashes.
	for _, ok := range []string{"relay-token", "token.json", "my-file", "a", "x1"} {
		got, err := validateCredentialBasename(ok)
		if err != nil {
			t.Errorf("validateCredentialBasename(%q): unexpected error: %v", ok, err)
		}
		if got != ok {
			t.Errorf("validateCredentialBasename(%q) = %q, want %q", ok, got, ok)
		}
	}

	// Reject: empty, whitespace, dot-segments, separators, env: prefix, long.
	for _, bad := range []string{
		"",
		"   ",
		".",
		"..",
		"a/b",
		"../escape",
		"env:RELAY_TOKEN",
		"env:token",
		string(make([]byte, 256)), // 256 zero bytes, exceeds 255
	} {
		if _, err := validateCredentialBasename(bad); err == nil {
			t.Errorf("validateCredentialBasename(%q): expected error, got nil", bad)
		}
	}
}

// --- parseMCPBindingEntry credential cases ----------------------------------

func TestParseMCPBindingEntryCredentialValid(t *testing.T) {
	t.Parallel()

	entry := "channel=main,command=node relay-mcp-server.mjs,credential=relay-token,credential-command=node"
	binding, err := parseMCPBindingEntry(entry, MCPTransportStdio, testCredentialLookupEnv(t, nil))
	if err != nil {
		t.Fatalf("parseMCPBindingEntry: %v", err)
	}
	if binding.Channel.Canonical() != types.Channel("main") {
		t.Errorf("channel = %q, want main", binding.Channel)
	}
	if binding.CredentialFile != "relay-token" {
		t.Errorf("CredentialFile = %q, want relay-token", binding.CredentialFile)
	}
	if binding.CredentialCommand != "node" {
		t.Errorf("CredentialCommand = %q, want node", binding.CredentialCommand)
	}
}

func TestParseMCPBindingEntryCredentialMissingCommandRefused(t *testing.T) {
	t.Parallel()

	// credential is set but credential-command is missing: the binding
	// must be refused at config-parse time (fail-closed).
	entry := "channel=main,command=node relay-mcp-server.mjs,credential=relay-token"
	_, err := parseMCPBindingEntry(entry, MCPTransportStdio, testCredentialLookupEnv(t, nil))
	if err == nil {
		t.Fatal("expected error when credential is set without credential-command")
	}
}

func TestParseMCPBindingEntryCredentialBasenameRejected(t *testing.T) {
	t.Parallel()

	cases := []string{
		"channel=main,command=node relay-mcp-server.mjs,credential=../evil,credential-command=node",
		"channel=main,command=node relay-mcp-server.mjs,credential=a/b,credential-command=node",
		"channel=main,command=node relay-mcp-server.mjs,credential=env:RELAY_TOKEN,credential-command=node",
		"channel=main,command=node relay-mcp-server.mjs,credential=,credential-command=node",
		"channel=main,command=node relay-mcp-server.mjs,credential=relay-token,credential-command=a/b",
	}
	for _, entry := range cases {
		if _, err := parseMCPBindingEntry(entry, MCPTransportStdio, testCredentialLookupEnv(t, nil)); err == nil {
			t.Errorf("entry %q: expected error, got nil", entry)
		}
	}
}

// --- buildMCPConfig main projection ----------------------------------------

// TestBuildMCPConfigMainProjectionCarriesCredentials verifies that when the
// main channel binding is a stdio binding with a credential, the projected
// MCPConfig carries CredentialFile and CredentialCommand so legacy callers
// that use cfg.CommandArgs / cfg.CredentialFile still hit the injection
// guard. This guards the regression where the projection dropped these
// fields.
func TestBuildMCPConfigMainProjectionCarriesCredentials(t *testing.T) {
	t.Parallel()

	fs := newCredentialFlagSet(t,
		"--mcp.command", "channel=main,command=node relay-mcp-server.mjs,credential=relay-token,credential-command=node",
	)
	cfg, err := LoadFromFlagSet(fs, testCredentialLookupEnv(t, map[string]string{
		"CONTROL_PLANE_TUNNEL_ID": testTunnelID,
		"CONTROL_PLANE_API_KEY":   "fake-test-api-key-value",
	}))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}

	main := cfg.MCP.MainChannelBinding()
	if main == nil {
		t.Fatal("main channel binding is nil")
	}
	if main.CredentialFile != "relay-token" {
		t.Errorf("binding.CredentialFile = %q, want relay-token", main.CredentialFile)
	}
	if main.CredentialCommand != "node" {
		t.Errorf("binding.CredentialCommand = %q, want node", main.CredentialCommand)
	}

	// The projection into cfg.MCP must carry the credential fields so that
	// legacy transport construction from cfg.CommandArgs still reaches the
	// fail-closed guard.
	if cfg.MCP.CredentialFile != "relay-token" {
		t.Errorf("cfg.MCP.CredentialFile = %q, want relay-token", cfg.MCP.CredentialFile)
	}
	if cfg.MCP.CredentialCommand != "node" {
		t.Errorf("cfg.MCP.CredentialCommand = %q, want node", cfg.MCP.CredentialCommand)
	}
	if cfg.MCP.Command == "" || len(cfg.MCP.CommandArgs) == 0 {
		t.Errorf("main projection dropped command: Command=%q CommandArgs=%v", cfg.MCP.Command, cfg.MCP.CommandArgs)
	}
}

// TestBuildMCPConfigNoCredentialLeavesProjectionEmpty verifies that a main
// stdio binding without a credential leaves the projected MCPConfig
// credential fields empty, preserving legacy inheritance behavior.
func TestBuildMCPConfigNoCredentialLeavesProjectionEmpty(t *testing.T) {
	t.Parallel()

	fs := newCredentialFlagSet(t,
		"--mcp.command", "channel=main,command=true",
	)
	cfg, err := LoadFromFlagSet(fs, testCredentialLookupEnv(t, map[string]string{
		"CONTROL_PLANE_TUNNEL_ID": testTunnelID,
		"CONTROL_PLANE_API_KEY":   "fake-test-api-key-value",
	}))
	if err != nil {
		t.Fatalf("LoadFromFlagSet: %v", err)
	}
	if cfg.MCP.CredentialFile != "" {
		t.Errorf("cfg.MCP.CredentialFile = %q, want empty", cfg.MCP.CredentialFile)
	}
	if cfg.MCP.CredentialCommand != "" {
		t.Errorf("cfg.MCP.CredentialCommand = %q, want empty", cfg.MCP.CredentialCommand)
	}
}
