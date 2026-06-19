// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package exec wraps command execution behind a Runner interface so backend
// adapters can be unit-tested without root or the real tools. The OS runner
// always pins the C locale for stable, parseable output and never builds a
// shell string — arguments are passed as a slice, so untrusted input cannot be
// interpreted by a shell.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Result is the captured output of a command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Out returns stdout as a trimmed string.
func (r Result) Out() string { return strings.TrimRight(string(r.Stdout), "\n") }

// Runner executes external commands.
type Runner interface {
	// Run executes name with args and returns the captured result. A non-zero
	// exit returns a non-nil error along with a populated Result.
	Run(ctx context.Context, name string, args ...string) (Result, error)
	// RunInput is Run with data written to the command's stdin (for tools that
	// read a request on stdin, e.g. socat to a socket, or Wazuh's AR scripts).
	RunInput(ctx context.Context, stdin []byte, name string, args ...string) (Result, error)
	// LookPath reports whether name is resolvable on PATH.
	LookPath(name string) (string, error)
}

// OSRunner is the production Runner backed by os/exec.
type OSRunner struct {
	// ExtraEnv is appended to the locale-pinned base environment.
	ExtraEnv []string
}

// New returns an OS-backed Runner.
func New() *OSRunner { return &OSRunner{} }

// Run executes the command with a C locale, inheriting the parent environment
// minus any locale variables (which are forced to C for deterministic parsing).
func (r *OSRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	return r.RunInput(ctx, nil, name, args...)
}

// RunInput is Run with stdin fed from the given bytes.
func (r *OSRunner) RunInput(ctx context.Context, stdin []byte, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = cLocaleEnv(r.ExtraEnv)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		}
		return res, err
	}
	return res, nil
}

// LookPath resolves name against the current PATH.
func (r *OSRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

// cLocaleEnv returns the parent environment with LC_*/LANG/LANGUAGE stripped and
// LC_ALL=C / LANG=C appended, plus any extra entries.
func cLocaleEnv(extra []string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra)+2)
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "LC_ALL", "LANG", "LANGUAGE",
			"LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MESSAGES":
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "LC_ALL=C", "LANG=C")
	out = append(out, extra...)
	return out
}

// --- Test double -----------------------------------------------------------

// FakeResponse is a canned reply for a FakeRunner key.
type FakeResponse struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// FakeRunner replays canned responses keyed by the full command line. Tests
// register golden output and assert on the recorded Calls.
type FakeRunner struct {
	Responses map[string]FakeResponse
	Missing   []string          // PATH entries that should be reported absent by LookPath
	Calls     []string          // invocation keys, in order
	Inputs    map[string]string // last stdin seen per invocation key (from RunInput)
}

// NewFake returns an empty FakeRunner.
func NewFake() *FakeRunner {
	return &FakeRunner{Responses: map[string]FakeResponse{}, Inputs: map[string]string{}}
}

// Set registers a response for a command invocation.
func (f *FakeRunner) Set(stdout string, exitCode int, name string, args ...string) {
	f.Responses[Key(name, args)] = FakeResponse{Stdout: stdout, ExitCode: exitCode}
}

// Run looks up a canned response for the invocation; an unregistered command is
// a test error so missing fixtures surface loudly.
func (f *FakeRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	k := Key(name, args)
	f.Calls = append(f.Calls, k)
	resp, ok := f.Responses[k]
	if !ok {
		return Result{ExitCode: 127}, fmt.Errorf("fakerunner: no canned response for %q", k)
	}
	res := Result{Stdout: []byte(resp.Stdout), Stderr: []byte(resp.Stderr), ExitCode: resp.ExitCode}
	if resp.Err != nil {
		return res, resp.Err
	}
	if resp.ExitCode != 0 {
		return res, fmt.Errorf("fakerunner: %q exited %d", k, resp.ExitCode)
	}
	return res, nil
}

// RunInput records the stdin under the invocation key, then behaves like Run.
func (f *FakeRunner) RunInput(ctx context.Context, stdin []byte, name string, args ...string) (Result, error) {
	if f.Inputs == nil {
		f.Inputs = map[string]string{}
	}
	f.Inputs[Key(name, args)] = string(stdin)
	return f.Run(ctx, name, args...)
}

// LookPath reports name as present unless it was registered in Missing.
func (f *FakeRunner) LookPath(name string) (string, error) {
	for _, m := range f.Missing {
		if m == name {
			return "", fmt.Errorf("exec: %q not found in $PATH", name)
		}
	}
	return "/usr/bin/" + name, nil
}

// Key builds the stable lookup key for an invocation.
func Key(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

// SortedKeys returns the registered response keys in deterministic order
// (handy for debugging a missing-fixture failure).
func (f *FakeRunner) SortedKeys() []string {
	keys := make([]string, 0, len(f.Responses))
	for k := range f.Responses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
