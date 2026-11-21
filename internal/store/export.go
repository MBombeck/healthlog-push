package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"errors"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// ExportFormat identifies the registry export file.
const ExportFormat = "healthlog-push-registry-v1"

// Export is the daily registry export: instances and the denylist, nothing else. No bindings, no counters,
// no key material other than the instances' public keys.
type Export struct {
	Format    string         `json:"format"`
	Day       string         `json:"day"`
	Instances []ExportedInst `json:"instances"`
	Denylist  []ExportedDeny `json:"denylist"`
	// BlockedPairs are the device opt-outs ("stop pushes from this server"). They must survive a restore,
	// so they travel in the export in their minimal form only.
	BlockedPairs []ExportedBlock `json:"blockedPairs"`
	// BlockedTokens are operator abuse blocks (admin block-token), in the same minimal form.
	BlockedTokens []ExportedBlock `json:"blockedTokens"`
}

// ReasonOperatorBlock is the reason code of a token blocked by the operator.
const ReasonOperatorBlock = "operator_block"

// ExportedDeny is a denylist entry: instance id (already part of the instance list), reason code from the
// closed set and expiry day.
type ExportedDeny struct {
	InstanceID string `json:"instanceId"`
	Reason     string `json:"reason"`
	ExpiresDay string `json:"expiresDay"`
}

// ReasonDeviceOptOut is the reason code of a pair blocked by the device itself.
const ReasonDeviceOptOut = "device_opt_out"

// ExportedBlock is a blocked device-instance pair: the keyed pair hash, the reason code and the expiry day.
type ExportedBlock struct {
	Pair       string `json:"pair"`       // hex of the stored keyed hash (pair or token)
	Reason     string `json:"reason"`     // ReasonDeviceOptOut or ReasonOperatorBlock
	ExpiresDay string `json:"expiresDay"` // YYYY-MM-DD; the block is dropped after this day
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
	ReasonDay        int    `json:"reasonDay,omitempty"`
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
	ex := &Export{Format: ExportFormat, Day: DayString(today), Instances: []ExportedInst{}, Denylist: []ExportedDeny{},
		BlockedPairs: []ExportedBlock{}, BlockedTokens: []ExportedBlock{}}
	for _, d := range deny {
		if today-d.Day <= RetainBlocks { // expired entries never leave the database
			ex.Denylist = append(ex.Denylist, ExportedDeny{InstanceID: d.InstanceID, Reason: d.Reason, ExpiresDay: DayString(d.Day + RetainBlocks)})
		}
	}
	collect := func(bucket []byte, reason string, out *[]ExportedBlock) func(tx *bolt.Tx) error {
		return func(tx *bolt.Tx) error {
			return tx.Bucket(bucket).ForEach(func(k, v []byte) error {
				d, _ := strconv.Atoi(string(v))
				if today-d > RetainBlocks {
					return nil
				}
				*out = append(*out, ExportedBlock{Pair: hex.EncodeToString(k), Reason: reason, ExpiresDay: DayString(d + RetainBlocks)})
				return nil
			})
		}
	}
	if err := s.db.View(collect(bBlockedPairs, ReasonDeviceOptOut, &ex.BlockedPairs)); err != nil {
		return nil, err
	}
	if err := s.db.View(collect(bBlockedToken, ReasonOperatorBlock, &ex.BlockedTokens)); err != nil {
		return nil, err
	}
	for _, in := range ins {
		// A suspended or revoked record expires with its denylist entry; it is not exported after that.
		if (in.Tier == TierRevoked || in.Tier == TierSuspended) && today-in.ReasonDay > RetainBlocks {
			continue
		}
		ex.Instances = append(ex.Instances, ExportedInst{
			ID: in.ID, PublicKey: in.PublicKey, Tier: in.Tier, Reason: in.Reason, CreatedDay: in.CreatedDay,
			DeviceLimit: in.DeviceLimit, FirstDeliveryDay: in.FirstDeliveryDay, ReasonDay: in.ReasonDay,
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
			LastSeenWeek: Week(today), DeviceLimit: e.DeviceLimit, FirstDeliveryDay: e.FirstDeliveryDay, ReasonDay: e.ReasonDay,
		}
		if err := s.PutInstance(in); err != nil {
			return n, err
		}
		n++
	}
	for _, d := range ex.Denylist {
		exp, err := ParseDayString(d.ExpiresDay)
		if err != nil || exp < today || !Reasons[d.Reason] {
			continue
		}
		if err := s.PutDeny(&DenyEntry{InstanceID: d.InstanceID, Reason: d.Reason, Day: exp - RetainBlocks}); err != nil {
			return n, err
		}
	}
	for _, set := range []struct {
		blocks []ExportedBlock
		reason string
		bucket []byte
	}{{ex.BlockedPairs, ReasonDeviceOptOut, bBlockedPairs}, {ex.BlockedTokens, ReasonOperatorBlock, bBlockedToken}} {
		for _, b := range set.blocks {
			k, err := hex.DecodeString(b.Pair)
			exp, derr := ParseDayString(b.ExpiresDay)
			if err != nil || len(k) != sha256.Size || derr != nil || b.Reason != set.reason || exp < today {
				continue
			}
			bucket := set.bucket
			if err := s.update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucket).Put(k, []byte(strconv.Itoa(exp-RetainBlocks)))
			}); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}
