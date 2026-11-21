package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// ExportFormat identifies the registry export file.
const ExportFormat = "healthlog-push-registry-v1"

// Export is the daily registry export: instances and the denylist, nothing else. No bindings, no counters,
// no key material other than the instances' public keys.
type Export struct {
	Format    string         `json:"format"`
	Day       string         `json:"day"`
	Instances []ExportedInst `json:"instances"`
	Denylist  []*DenyEntry   `json:"denylist"`
}

// ExportedInst is the exported subset of an instance.
type ExportedInst struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"publicKey"`
	Tier             string `json:"tier"`
	Reason           string `json:"reason,omitempty"`
	CreatedDay       int    `json:"createdDay"`
	DeviceLimit      int    `json:"deviceLimit"`
	FirstDeliveryDay int    `json:"firstDeliveryDay,omitempty"`
}

// BuildExport assembles the export from the store.
func (s *Store) BuildExport(today int) (*Export, error) {
	ins, err := s.Instances()
	if err != nil {
		return nil, err
	}
	deny, err := s.Denylist()
	if err != nil {
		return nil, err
	}
	ex := &Export{Format: ExportFormat, Day: DayString(today), Instances: []ExportedInst{}, Denylist: deny}
	if ex.Denylist == nil {
		ex.Denylist = []*DenyEntry{}
	}
	for _, in := range ins {
		ex.Instances = append(ex.Instances, ExportedInst{
			ID: in.ID, PublicKey: in.PublicKey, Tier: in.Tier, Reason: in.Reason, CreatedDay: in.CreatedDay,
			DeviceLimit: in.DeviceLimit, FirstDeliveryDay: in.FirstDeliveryDay,
		})
	}
	return ex, nil
}

// WriteExport writes the export atomically to dir/registry.json with mode 0600.
func WriteExport(dir string, ex *Export) error {
	b, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".registry-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "registry.json"))
}

// ReadExport reads and validates an export file.
func ReadExport(path string) (*Export, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, err
	}
	var ex Export
	if err := json.Unmarshal(b, &ex); err != nil {
		return nil, err
	}
	if ex.Format != ExportFormat {
		return nil, errors.New("unknown export format")
	}
	return &ex, nil
}

// Import loads instances and denylist entries from an export, skipping ids or keys that already exist.
// It returns the number of instances imported.
func (s *Store) Import(ex *Export, today int) (int, error) {
	existing, err := s.Instances()
	if err != nil {
		return 0, err
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, in := range existing {
		ids[in.ID] = true
		keys[string(in.PublicKey)] = true
	}
	n := 0
	for _, e := range ex.Instances {
		if ids[e.ID] || keys[string(e.PublicKey)] || len(e.PublicKey) != 32 {
			continue
		}
		in := &Instance{
			ID: e.ID, PublicKey: e.PublicKey, Tier: e.Tier, Reason: e.Reason, CreatedDay: e.CreatedDay,
			LastSeenWeek: Week(today), DeviceLimit: e.DeviceLimit, FirstDeliveryDay: e.FirstDeliveryDay,
		}
		if err := s.PutInstance(in); err != nil {
			return n, err
		}
		n++
	}
	for _, d := range ex.Denylist {
		if err := s.PutDeny(d); err != nil {
			return n, err
		}
	}
	return n, nil
}
