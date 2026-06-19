// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package hosts

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/model"
)

// sinkholeTargets are the addresses a domain is mapped to in order to blackhole
// it. 0.0.0.0 and :: are unambiguous; 127.0.0.1/::1 only count when the mapped
// name is not a normal loopback name (see loopbackNames).
var sinkholeTargets = map[string]bool{"0.0.0.0": true, "::": true, "127.0.0.1": true, "::1": true}

var unspecifiedTargets = map[string]bool{"0.0.0.0": true, "::": true}

// loopbackNames are the standard local hostnames that map to 127.0.0.1/::1 and
// must not be mistaken for sinkholed domains.
var loopbackNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true,
	"localhost4": true, "localhost4.localdomain4": true,
	"localhost6": true, "localhost6.localdomain6": true,
	"ip6-localhost": true, "ip6-loopback": true,
	"ip6-allnodes": true, "ip6-allrouters": true,
}

// ListBans scans the whole hosts file for domain sinkholes, flagging entries
// outside omniban's managed block as External.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	lines, err := readFile(b.path)
	if err != nil {
		return nil, err
	}
	var out []model.Entry
	inBlock := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case line == config.HostsBeginMarker:
			inBlock = true
			continue
		case line == config.HostsEndMarker:
			inBlock = false
			continue
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		}
		target, names := splitHostsLine(line)
		if !sinkholeTargets[target] {
			continue
		}
		for _, name := range names {
			if !isSinkhole(target, name) {
				continue
			}
			out = append(out, model.Entry{
				Value:     name,
				Family:    model.FamilyDomain,
				Scope:     model.ScopeDomain,
				Kind:      model.KindBan,
				Direction: model.DirOutbound,
				Origin:    model.OriginHosts,
				Backend:   string(model.OriginHosts),
				Hostname:  name,
				Detail:    target,
				External:  !inBlock,
				Raw:       line,
			})
		}
	}
	return out, nil
}

// Ban sinkholes a domain by mapping it to 0.0.0.0 and ::1 inside the managed
// block, creating the block if needed and backing up the file first.
func (b *Backend) Ban(_ context.Context, req model.ActionRequest) (model.Result, error) {
	domain := strings.ToLower(strings.TrimSpace(req.Value))
	want := []string{"0.0.0.0 " + domain, "::1 " + domain}
	res := model.Result{
		Backend: string(model.OriginHosts), Action: "ban", Value: domain,
		Commands: []string{fmt.Sprintf("add %q to the omniban block in %s", strings.Join(want, " / "), b.path)},
		DryRun:   req.DryRun,
	}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	lines, err := readFile(b.path)
	if err != nil {
		return res, err
	}
	updated, changed := addToBlock(lines, want)
	if !changed {
		res.Message = "already present"
		return res, nil
	}
	if err := backupAndWrite(b.path, updated); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Unban removes every sinkhole mapping for the domain, wherever it lives —
// including a user-added entry outside the managed block.
func (b *Backend) Unban(_ context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	domain := strings.ToLower(strings.TrimSpace(e.Value))
	res := model.Result{
		Backend: string(model.OriginHosts), Action: "unban", Value: domain,
		Commands: []string{fmt.Sprintf("remove sinkhole mappings for %q from %s", domain, b.path)},
		DryRun:   dryRun,
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	lines, err := readFile(b.path)
	if err != nil {
		return res, err
	}
	updated, changed := removeDomain(lines, domain)
	if !changed {
		res.Message = "not present"
		return res, nil
	}
	if err := backupAndWrite(b.path, updated); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// --- helpers ---------------------------------------------------------------

func isSinkhole(target, name string) bool {
	if unspecifiedTargets[target] {
		return true
	}
	// 127.0.0.1 / ::1: only a sinkhole when the name is not a loopback name.
	return !loopbackNames[strings.ToLower(name)]
}

// splitHostsLine separates the address from the hostnames, dropping any inline
// comment.
func splitHostsLine(line string) (target string, names []string) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// addToBlock inserts any of want not already in the managed block, creating the
// block at end of file if it does not exist.
func addToBlock(lines, want []string) ([]string, bool) {
	present := make(map[string]bool)
	begin, end := -1, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == config.HostsBeginMarker {
			begin = i
		}
		if t == config.HostsEndMarker {
			end = i
		}
		present[strings.Join(strings.Fields(t), " ")] = true
	}
	var missing []string
	for _, w := range want {
		if !present[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		return lines, false
	}
	if begin >= 0 && end > begin {
		out := make([]string, 0, len(lines)+len(missing))
		out = append(out, lines[:end]...)
		out = append(out, missing...)
		out = append(out, lines[end:]...)
		return out, true
	}
	// No block yet: append a fresh one.
	out := append([]string{}, lines...)
	if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
		out = append(out, "")
	}
	out = append(out, config.HostsBeginMarker)
	out = append(out, missing...)
	out = append(out, config.HostsEndMarker)
	return out, true
}

// removeDomain drops the domain from every sinkhole line; a line left with only
// an address is removed entirely. Marker lines for an emptied block are kept
// (harmless) — only mappings are touched.
func removeDomain(lines []string, domain string) ([]string, bool) {
	changed := false
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		target, names := splitHostsLine(line)
		if target == "" || !sinkholeTargets[target] {
			out = append(out, raw)
			continue
		}
		var kept []string
		for _, n := range names {
			if strings.EqualFold(n, domain) {
				changed = true
				continue
			}
			kept = append(kept, n)
		}
		if len(kept) == len(names) {
			out = append(out, raw) // domain not on this line
			continue
		}
		if len(kept) > 0 {
			out = append(out, target+" "+strings.Join(kept, " "))
		}
		// else: line dropped entirely
	}
	return out, changed
}

func readFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

func backupAndWrite(path string, lines []string) error {
	mode := os.FileMode(0o644)
	if data, err := os.ReadFile(path); err == nil {
		if fi, serr := os.Stat(path); serr == nil {
			mode = fi.Mode().Perm()
		}
		if werr := os.WriteFile(path+".omniban.bak", data, mode); werr != nil {
			return fmt.Errorf("backup %s: %w", path, werr)
		}
	}
	out := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
