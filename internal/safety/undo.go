// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package safety

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxUndoRecords caps the journal so it cannot grow without bound.
const maxUndoRecords = 200

// UndoRecord describes the inverse of a mutating action, enough to replay it.
type UndoRecord struct {
	Time      string `json:"time"`
	InverseOp string `json:"inverse_op"` // ban | unban | allow | unallow
	Backend   string `json:"backend"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Kind      string `json:"kind"`
	Direction string `json:"direction"`
	Note      string `json:"note,omitempty"`
}

// Journal is an append-only undo log persisted as JSON lines under state_dir.
type Journal struct {
	mu   sync.Mutex
	path string
}

// NewJournal returns a Journal at <stateDir>/undo.json. An empty stateDir
// disables it (Push/Pop become no-ops).
func NewJournal(stateDir string) *Journal {
	if stateDir == "" {
		return &Journal{}
	}
	return &Journal{path: filepath.Join(stateDir, "undo.json")}
}

// Push appends a record, trimming the journal to the most recent maxUndoRecords.
func (j *Journal) Push(r UndoRecord) error {
	if j == nil || j.path == "" {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	records, err := j.readLocked()
	if err != nil {
		return err
	}
	records = append(records, r)
	if len(records) > maxUndoRecords {
		records = records[len(records)-maxUndoRecords:]
	}
	return j.writeLocked(records)
}

// Pop removes and returns the most recent record. ok is false when empty.
func (j *Journal) Pop() (rec UndoRecord, ok bool, err error) {
	if j == nil || j.path == "" {
		return UndoRecord{}, false, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	records, err := j.readLocked()
	if err != nil || len(records) == 0 {
		return UndoRecord{}, false, err
	}
	rec = records[len(records)-1]
	if err := j.writeLocked(records[:len(records)-1]); err != nil {
		return UndoRecord{}, false, err
	}
	return rec, true, nil
}

func (j *Journal) readLocked() ([]UndoRecord, error) {
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []UndoRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r UndoRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // skip corrupt lines rather than fail the whole journal
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func (j *Journal) writeLocked(records []UndoRecord) (err error) {
	if err := os.MkdirAll(filepath.Dir(j.path), 0o755); err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp, j.path)
		}
	}()
	w := bufio.NewWriter(f)
	for _, r := range records {
		line, mErr := json.Marshal(r)
		if mErr != nil {
			return mErr
		}
		if _, wErr := w.Write(append(line, '\n')); wErr != nil {
			return wErr
		}
	}
	return w.Flush()
}
