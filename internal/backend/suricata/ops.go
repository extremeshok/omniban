// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package suricata

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// datasetType is the Suricata dataset value type for IP blocks. For "ip" the
// data is given to the socket — and stored in the save file — as a plain
// address in standard notation (IPv4 dotted-quad or IPv6), never base64.
const datasetType = "ip"

// ListBans reads the dataset save/state file best-effort and reports each
// address as an inbound ban. Suricata writes one IP per line in standard
// notation for "ip"/"ipv4"/"ipv6" datasets (base64 applies only to "string"
// datasets), so each non-empty, non-comment line is a single address. A missing
// file is treated as empty: the dataset may live only in memory until Suricata
// next persists it.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	data, err := os.ReadFile(b.stateFile) //nolint:gosec // operator-configured dataset save file
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", b.stateFile, err)
	}
	var out []model.Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A plain dataset stores one address per line; a datarep dataset would
		// append ",<value>". Keep only the address token defensively.
		value := line
		if i := strings.IndexByte(value, ','); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		fam := familyOf(value)
		if fam == "" {
			continue // not a recognizable address — skip rather than invent
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    fam,
			Scope:     model.ScopeIP,
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginSuricata,
			Backend:   string(model.OriginSuricata),
			Detail:    b.set,
			Raw:       line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", b.stateFile, err)
	}
	return out, nil
}

// Ban adds the address to omniban's dataset via the command socket:
// suricatasc -c "dataset-add <set> ip <value>" <socket>.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	c := b.socketCmd("dataset-add", req.Value)
	return b.run(ctx, req.DryRun, "ban", req.Value, c)
}

// Unban removes the address from omniban's dataset via the command socket:
// suricatasc -c "dataset-remove <set> ip <value>" <socket>.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	c := b.socketCmd("dataset-remove", e.Value)
	return b.run(ctx, dryRun, "unban", e.Value, c)
}

// socketCmd builds the suricatasc invocation for a dataset operation. The
// dataset command is a single quoted argument to -c; the socket path is the
// positional argument.
func (b *Backend) socketCmd(op, value string) []string {
	return []string{"suricatasc", "-c", op + " " + b.set + " " + datasetType + " " + value, b.socket}
}

// run executes (or, in dry-run, only records) a single suricatasc invocation,
// returning a Result whose Commands field holds the exact invocation.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, c []string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginSuricata), Action: action, Value: value, DryRun: dryRun}
	res.Commands = append(res.Commands, strings.Join(c, " "))
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, c[0], c[1:]...); err != nil {
		return res, fmt.Errorf("%s: %w", strings.Join(c, " "), err)
	}
	res.Changed = true
	return res, nil
}

func familyOf(value string) model.Family {
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is6() && !addr.Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	return ""
}
