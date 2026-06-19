// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package wazuh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/extremeshok/omniban/internal/model"
)

// arProgram is the active-response program name omniban drives. The firewall-drop
// script reads its request as JSON on stdin (Wazuh 4.x) and blocks/unblocks the
// srcip with the host firewall.
const arProgram = "firewall-drop"

// arRequest is the JSON request fed to the firewall-drop script on stdin. It
// mirrors the structure Wazuh's execd sends: a command ("add"/"delete") and an
// alert carrying the source IP to act on.
type arRequest struct {
	Version    int      `json:"version"`
	Origin     arOrigin `json:"origin"`
	Command    string   `json:"command"`
	Parameters arParams `json:"parameters"`
}

type arOrigin struct {
	Name   string `json:"name"`
	Module string `json:"module"`
}

type arParams struct {
	Alert   arAlert `json:"alert"`
	Program string  `json:"program"`
}

type arAlert struct {
	Data arData `json:"data"`
}

type arData struct {
	SrcIP string `json:"srcip"`
}

// script returns the absolute path to the firewall-drop active-response script.
func (b *Backend) script() string {
	return b.dir + "/active-response/bin/" + arProgram
}

// logFile returns the absolute path to the active-responses log.
func (b *Backend) logFile() string {
	return b.dir + "/logs/active-responses.log"
}

// Ban blocks an IP through the firewall-drop active-response script, feeding it
// an "add" request on stdin.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.invoke(ctx, "add", "ban", req.Value, req.DryRun)
}

// Unban removes a firewall-drop block by feeding the script a "delete" request
// on stdin (the same request shape the daemon sends to revert the action).
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.invoke(ctx, "delete", "unban", e.Value, dryRun)
}

// invoke builds the JSON request for the given command and either records it
// (dry-run) or pipes it to the firewall-drop script on stdin.
func (b *Backend) invoke(ctx context.Context, command, action, value string, dryRun bool) (model.Result, error) {
	request, err := buildRequest(command, value)
	if err != nil {
		return model.Result{}, fmt.Errorf("wazuh: build %s request: %w", command, err)
	}
	// Wazuh 4.x active-response uses a stateful two-message handshake: the script
	// reads the command, replies with a "check_keys" request, and waits for a
	// "continue" (or "abort") before applying the firewall change. We send both
	// messages (newline-delimited) so the buffered "continue" is read after the
	// handshake.
	cont, err := buildRequest("continue", value)
	if err != nil {
		return model.Result{}, fmt.Errorf("wazuh: build continue request: %w", err)
	}
	payload := make([]byte, 0, len(request)+len(cont)+2)
	payload = append(payload, request...)
	payload = append(payload, '\n')
	payload = append(payload, cont...)
	payload = append(payload, '\n')

	script := b.script()
	res := model.Result{
		Backend: string(model.OriginWazuh),
		Action:  action,
		Value:   value,
		Commands: []string{
			fmt.Sprintf("%s <<< %s (+continue)", script, string(request)),
		},
		DryRun: dryRun,
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.RunInput(ctx, payload, script); err != nil {
		return res, fmt.Errorf("%s: %w", script, err)
	}
	res.Changed = true
	return res, nil
}

// buildRequest marshals the active-response request JSON for the given command
// and source IP. The structure matches what Wazuh's execd feeds the script.
func buildRequest(command, value string) ([]byte, error) {
	req := arRequest{
		Version: 1,
		Origin:  arOrigin{Name: "omniban", Module: "omniban"},
		Command: command,
		Parameters: arParams{
			Alert:   arAlert{Data: arData{SrcIP: value}},
			Program: arProgram,
		},
	}
	return json.Marshal(req)
}

// ListBans parses the active-responses log and reports the currently-active
// firewall-drop blocks: every "add" for an IP that has no later "delete". A
// missing log is treated as no bans.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	data, err := os.ReadFile(b.logFile()) //nolint:gosec // operator-configured OSSEC install dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", b.logFile(), err)
	}
	return parseActiveResponses(data), nil
}

// arEvent is one parsed firewall-drop add/delete from the log.
type arEvent struct {
	command string
	srcip   string
	when    time.Time
	raw     string
}

// parseActiveResponses scans the active-responses log for firewall-drop add/
// delete events and returns the set of IPs whose most recent action was "add"
// (i.e. still blocked), ordered by first-seen for determinism.
func parseActiveResponses(data []byte) []model.Entry {
	var order []string
	latest := map[string]arEvent{}
	seen := map[string]bool{}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		ev, ok := parseLine(sc.Text())
		if !ok {
			continue
		}
		if !seen[ev.srcip] {
			seen[ev.srcip] = true
			order = append(order, ev.srcip)
		}
		// Later lines win: the log is append-only and chronological, so the last
		// add/delete we see for an IP is its current state.
		latest[ev.srcip] = ev
	}

	out := make([]model.Entry, 0, len(order))
	for _, ip := range order {
		ev := latest[ip]
		if ev.command != "add" {
			continue // most recent action was a delete: no longer blocked
		}
		e := model.Entry{
			Value:     ev.srcip,
			Family:    familyOf(ev.srcip),
			Scope:     scopeOf(ev.srcip),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginWazuh,
			Backend:   string(model.OriginWazuh),
			Detail:    arProgram,
			Raw:       ev.raw,
		}
		if !ev.when.IsZero() {
			t := ev.when
			e.CreatedAt = &t
		}
		out = append(out, e)
	}
	return out
}

// parseLine parses one active-responses log line. A firewall-drop line looks
// like:
//
//	2023/10/01 16:20:56 active-response/bin/firewall-drop: {"version":1,...,"command":"add","parameters":{"alert":{"data":{"srcip":"1.2.3.4"}},...}}
//
// Status lines (Starting/Ended/...) carry no JSON payload and are skipped. The
// timestamp is best-effort; a line whose JSON omits a valid srcip is skipped.
func parseLine(line string) (arEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return arEvent{}, false
	}
	// The JSON payload (if any) starts at the first '{'. Everything before it is
	// the "TIMESTAMP script:" prefix.
	brace := strings.IndexByte(line, '{')
	if brace < 0 {
		return arEvent{}, false
	}
	prefix := line[:brace]
	if !strings.Contains(prefix, arProgram) {
		return arEvent{}, false
	}
	var req arRequest
	if err := json.Unmarshal([]byte(line[brace:]), &req); err != nil {
		return arEvent{}, false
	}
	ip := strings.TrimSpace(req.Parameters.Alert.Data.SrcIP)
	if ip == "" || familyOf(ip) == "" {
		return arEvent{}, false
	}
	cmd := strings.ToLower(strings.TrimSpace(req.Command))
	if cmd != "add" && cmd != "delete" {
		return arEvent{}, false
	}
	return arEvent{
		command: cmd,
		srcip:   ip,
		when:    parseTimestamp(prefix),
		raw:     line,
	}, true
}

// parseTimestamp extracts the leading "YYYY/MM/DD HH:MM:SS" timestamp from a log
// line prefix. It returns the zero time when the prefix is not a recognised
// timestamp.
func parseTimestamp(prefix string) time.Time {
	fields := strings.Fields(prefix)
	if len(fields) < 2 {
		return time.Time{}
	}
	stamp := fields[0] + " " + fields[1]
	t, err := time.ParseInLocation("2006/01/02 15:04:05", stamp, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}

func scopeOf(value string) model.Scope {
	if strings.Contains(value, "/") {
		return model.ScopeRange
	}
	return model.ScopeIP
}

func familyOf(value string) model.Family {
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is6() && !addr.Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	return ""
}
