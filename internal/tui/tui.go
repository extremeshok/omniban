// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package tui is the interactive Bubble Tea front-end: a filterable view of
// every ban and allow across all backends, with refresh and unban actions.
package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"

	"github.com/extremeshok/omniban/internal/manager"
	"github.com/extremeshok/omniban/internal/model"
)

// Run launches the interactive TUI bound to ctx and mgr.
func Run(ctx context.Context, mgr *manager.Manager) error {
	m := newModel(ctx, mgr)
	return tea.NewProgram(m, tea.WithAltScreen()).Start()
}

type view int

const (
	viewBans view = iota
	viewAllows
	viewStatus
)

type uiModel struct {
	ctx context.Context
	mgr *manager.Manager

	view    view
	bans    table.Model
	allows  table.Model
	status  []manager.Status
	warns   []string
	message string
	loading bool
	width   int
	height  int

	confirm *confirmState
}

type confirmState struct {
	value   string
	backend string
}

// --- messages --------------------------------------------------------------

type loadedMsg struct {
	status []manager.Status
	bans   []model.Entry
	allows []model.Entry
	warns  []string
	err    error
}

type actionDoneMsg struct {
	summary string
	err     error
}

func newModel(ctx context.Context, mgr *manager.Manager) *uiModel {
	return &uiModel{
		ctx:     ctx,
		mgr:     mgr,
		bans:    newTable(banColumns()),
		allows:  newTable(allowColumns()),
		loading: true,
		message: "loading…",
	}
}

func newTable(cols []table.Column) table.Model {
	return table.New(cols).
		Filtered(true).
		Focused(true).
		WithPageSize(15)
}

func banColumns() []table.Column {
	return []table.Column{
		table.NewFlexColumn("value", "VALUE", 3).WithFiltered(true),
		table.NewColumn("family", "FAMILY", 7),
		table.NewColumn("dir", "DIR", 8),
		table.NewColumn("origin", "ORIGIN", 10).WithFiltered(true),
		table.NewColumn("backend", "BACKEND", 10).WithFiltered(true),
		table.NewFlexColumn("detail", "DETAIL", 2).WithFiltered(true),
		table.NewColumn("expires", "EXPIRES", 16),
		table.NewFlexColumn("also", "ALSO", 2),
	}
}

func allowColumns() []table.Column {
	return []table.Column{
		table.NewFlexColumn("value", "VALUE", 3).WithFiltered(true),
		table.NewColumn("family", "FAMILY", 7),
		table.NewColumn("origin", "ORIGIN", 10).WithFiltered(true),
		table.NewColumn("backend", "BACKEND", 10).WithFiltered(true),
		table.NewFlexColumn("detail", "DETAIL", 2).WithFiltered(true),
	}
}

func (m *uiModel) Init() tea.Cmd { return m.loadCmd() }

func (m *uiModel) loadCmd() tea.Cmd {
	return func() tea.Msg {
		status := m.mgr.Detect(m.ctx)
		bans, w1, err := m.mgr.ListAll(m.ctx, model.KindBan)
		if err != nil {
			return loadedMsg{err: err}
		}
		allows, w2, err := m.mgr.ListAll(m.ctx, model.KindAllow)
		if err != nil {
			return loadedMsg{err: err}
		}
		return loadedMsg{status: status, bans: bans, allows: allows, warns: append(w1, w2...)}
	}
}

func (m *uiModel) unbanCmd(value, backend string) tea.Cmd {
	return func() tea.Msg {
		results, err := m.mgr.Unban(m.ctx, value, backend, false, false)
		if err != nil {
			return actionDoneMsg{err: err}
		}
		n := 0
		for _, r := range results {
			if r.Changed {
				n++
			}
		}
		return actionDoneMsg{summary: fmt.Sprintf("unbanned %s (%d backend change(s))", value, n)}
	}
}

func (m *uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		ps := msg.Height - 8
		if ps < 3 {
			ps = 3
		}
		m.bans = m.bans.WithTargetWidth(msg.Width).WithPageSize(ps)
		m.allows = m.allows.WithTargetWidth(msg.Width).WithPageSize(ps)
		return m, nil

	case loadedMsg:
		m.loading = false
		if msg.err != nil {
			m.message = "error: " + msg.err.Error()
			return m, nil
		}
		m.status = msg.status
		m.warns = msg.warns
		m.bans = m.bans.WithRows(banRows(msg.bans))
		m.allows = m.allows.WithRows(allowRows(msg.allows))
		m.message = fmt.Sprintf("%d bans, %d allows across %d backends", len(msg.bans), len(msg.allows), countInstalled(msg.status))
		return m, nil

	case actionDoneMsg:
		if msg.err != nil {
			m.message = "error: " + msg.err.Error()
			return m, nil
		}
		m.message = msg.summary
		m.loading = true
		return m, m.loadCmd()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, m.delegate(msg)
}

func (m *uiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While the active table's filter input is focused, route keys to it so the
	// user can type a filter without triggering shortcuts.
	if m.activeFilterFocused() {
		return m, m.delegate(msg)
	}

	if m.confirm != nil {
		switch msg.String() {
		case "y", "Y", "enter":
			c := m.confirm
			m.confirm = nil
			m.message = "unbanning " + c.value + "…"
			return m, m.unbanCmd(c.value, c.backend)
		default:
			m.confirm = nil
			m.message = "cancelled"
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.view = (m.view + 1) % 3
		return m, nil
	case "r":
		m.loading = true
		m.message = "refreshing…"
		return m, m.loadCmd()
	case "u":
		if m.view == viewBans {
			if row := m.bans.HighlightedRow(); row.Data != nil {
				m.confirm = &confirmState{
					value:   asString(row.Data["value"]),
					backend: asString(row.Data["backend"]),
				}
			}
		}
		return m, nil
	}
	return m, m.delegate(msg)
}

// delegate forwards a message to the active table (navigation, filtering).
func (m *uiModel) delegate(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch m.view {
	case viewBans:
		m.bans, cmd = m.bans.Update(msg)
	case viewAllows:
		m.allows, cmd = m.allows.Update(msg)
	}
	return cmd
}

func (m *uiModel) activeFilterFocused() bool {
	switch m.view {
	case viewBans:
		return m.bans.GetIsFilterInputFocused()
	case viewAllows:
		return m.allows.GetIsFilterInputFocused()
	}
	return false
}

func (m *uiModel) View() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("omniban") + "  " + tabsView(m.view))
	b.WriteByte('\n')
	b.WriteString(dimStyle.Render(m.message))
	b.WriteString("\n\n")

	switch m.view {
	case viewBans:
		b.WriteString(m.bans.View())
	case viewAllows:
		b.WriteString(m.allows.View())
	case viewStatus:
		b.WriteString(m.statusView())
	}

	b.WriteString("\n\n")
	if m.confirm != nil {
		b.WriteString(warnStyle.Render(fmt.Sprintf("Unban %s via %s? [y/N]", m.confirm.value, m.confirm.backend)))
	} else {
		b.WriteString(dimStyle.Render("tab: switch view · /: filter · u: unban · r: refresh · q: quit"))
	}
	return b.String()
}

func (m *uiModel) statusView() string {
	var b strings.Builder
	for _, s := range m.status {
		if !s.Detection.Installed {
			continue
		}
		mark := "·"
		if s.Detection.Active {
			mark = "●"
		}
		fmt.Fprintf(&b, "%s %-11s %-9s active=%-5t enforcing=%-5t %s\n",
			mark, s.Name, s.Layer, s.Detection.Active, s.Detection.Enforcing, s.Detection.Version)
		for _, w := range s.Detection.Warnings {
			b.WriteString(warnStyle.Render("    ! "+w) + "\n")
		}
	}
	for _, w := range m.warns {
		b.WriteString(warnStyle.Render("! "+w) + "\n")
	}
	return b.String()
}

// --- rendering helpers -----------------------------------------------------

var (
	headerStyle = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Faint(true)
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

func tabsView(active view) string {
	names := []string{"Bans", "Allows", "Status"}
	parts := make([]string, len(names))
	for i, n := range names {
		if view(i) == active {
			parts[i] = headerStyle.Render("[" + n + "]")
		} else {
			parts[i] = dimStyle.Render(n)
		}
	}
	return strings.Join(parts, " ")
}

func banRows(entries []model.Entry) []table.Row {
	rows := make([]table.Row, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, table.NewRow(table.RowData{
			"value":   e.Value,
			"family":  dash(string(e.Family)),
			"dir":     dash(string(e.Direction)),
			"origin":  string(e.Origin),
			"backend": e.Backend,
			"detail":  dash(e.Detail),
			"expires": expiresStr(e),
			"also":    dash(strings.Join(e.AlsoSeenIn, ",")),
		}))
	}
	return rows
}

func allowRows(entries []model.Entry) []table.Row {
	rows := make([]table.Row, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, table.NewRow(table.RowData{
			"value":   e.Value,
			"family":  dash(string(e.Family)),
			"origin":  string(e.Origin),
			"backend": e.Backend,
			"detail":  dash(e.Detail),
		}))
	}
	return rows
}

func countInstalled(status []manager.Status) int {
	n := 0
	for _, s := range status {
		if s.Detection.Installed {
			n++
		}
	}
	return n
}

func expiresStr(e model.Entry) string {
	if e.ExpiresAt == nil {
		return "permanent"
	}
	return e.ExpiresAt.Format("2006-01-02 15:04")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
