package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// ExportFormat identifies the registry export file.
const ExportFormat = "healthlog-push-registry-v2"

// Export is the daily registry export: instances and the blocks, nothing else. No bindings, no counters,
// no key material other than the instances' public keys. It is the root of trust after a database loss,
// so it is signed with the relay identity key and checked on import (see Seal and Open).
type Export struct {
	Format    string         `json:"format"`
	Host      string         `json:"host"`
	Day       string         `json:"day"`
	Instances []ExportedInst `json:"instances"`
	// BlockedPairs are the device opt-outs ("stop pushes from this server"), BlockedTokens the operator
	// abuse blocks, OptOutPins the binding keys that opted out. All in their minimal keyed-hash form.
	BlockedPairs  []ExportedBlock `json:"blockedPairs"`
	BlockedTokens []ExportedBlock `json:"blockedTokens"`
	OptOutPins    []ExportedBlock `json:"optOutPins"`
	// Signature is the relay identity key's Ed25519 signature over hl-relay-export-v1 (spec/statements.md)
	// of the export marshaled without this field.
	Signature string `json:"signature,omitempty"`
}

// Reason codes of exported blocks.
const (
	ReasonDeviceOptOut  = "device_opt_out"
	ReasonOperatorBlock = "operator_block"
	ReasonOptOutPin     = "device_opt_out_pin"
)

// ExportedBlock is a block in minimal form: the keyed hash, the reason code and the expiry day.
type ExportedBlock struct {
	Pair       string `json:"pair"`       // hex of the stored keyed hash
	Reason     string `json:"reason"`     // one of the reason codes above
	ExpiresDay string `json:"expiresDay"` // YYYY-MM-DD; the block is dropped after this day
}

// ExportedInst is the exported subset of an instance. A suspended or revoked instance travels with its
// tier, reason and day, so the block survives a restore.
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

// BuildExport assembles the unsigned export from the store.
func (s *Store) BuildExport(host string, today int) (*Export, error) {
	ins, err := s.Instances()
	if err != nil {
		return nil, err
	}
	ex := &Export{Format: ExportFormat, Host: host, Day: DayString(today), Instances: []ExportedInst{},
		BlockedPairs: []ExportedBlock{}, BlockedTokens: []ExportedBlock{}, OptOutPins: []ExportedBlock{}}
	sets := []struct {
		bucket []byte
		dayOf  func(k, v []byte) int
		reason string
		out    *[]ExportedBlock
	}{
		{bBlockedPairs, pairBlockDay, ReasonDeviceOptOut, &ex.BlockedPairs},
		{bBlockedTokens, tokenBlockDay, ReasonOperatorBlock, &ex.BlockedTokens},
		{bOptOutPins, pinDay, ReasonOptOutPin, &ex.OptOutPins},
	}
	err = s.db.View(func(tx *bolt.Tx) error {
		for _, set := range sets {
			err := tx.Bucket(set.bucket).ForEach(func(k, v []byte) error {
				if d := set.dayOf(k, v); today-d <= RetainBlocks { // expired blocks never leave the database
					*set.out = append(*set.out, ExportedBlock{Pair: hex.EncodeToString(k), Reason: set.reason, ExpiresDay: DayString(d + RetainBlocks)})
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, in := range ins {
		if (in.Tier == TierRevoked || in.Tier == TierSuspended) && today-in.ReasonDay > RetainBlocks {
			continue // a blocked record expires after the block retention
		}
		ex.Instances = append(ex.Instances, ExportedInst{
			ID: in.ID, PublicKey: in.PublicKey, Tier: in.Tier, Reason: in.Reason, CreatedDay: in.CreatedDay,
			DeviceLimit: in.DeviceLimit, FirstDeliveryDay: in.FirstDeliveryDay, ReasonDay: in.ReasonDay,
		})
	}
	return ex, nil
}

// SignedBytes returns the bytes the export signature covers: the export marshaled without Signature.
func (ex *Export) SignedBytes() ([]byte, error) {
	c := *ex
	c.Signature = ""
	return json.Marshal(&c)
}

// WriteExport writes the signed export atomically to dir/registry.json with mode 0600.
func WriteExport(dir string, ex *Export) error {
	if ex.Signature == "" {
		return errors.New("refusing to write an unsigned export")
	}
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

// ErrExportOutsideDir refuses an export path that leaves the export directory.
var ErrExportOutsideDir = errors.New("registry export must be a file inside the export directory")

// ReadExport reads an export file inside dir and checks its format. The caller verifies the signature.
// name is relative to dir or an absolute path under it (the operator's `recovery --from`); anything that
// resolves outside dir, by `..` or through a symbolic link, is refused, so the admin socket cannot be used
// to read other files of the container.
func ReadExport(dir, name string) (*Export, error) {
	rel, err := exportRel(dir, name)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(rel)
	if err != nil {
		return nil, err
	}
	var ex Export
	if err := json.Unmarshal(b, &ex); err != nil {
		return nil, err
	}
	if ex.Format != ExportFormat {
		return nil, fmt.Errorf("unknown export format %q, expected %q", ex.Format, ExportFormat)
	}
	return &ex, nil
}

// exportRel returns name as a clean path relative to dir, or ErrExportOutsideDir.
func exportRel(dir, name string) (string, error) {
	if dir == "" || name == "" {
		return "", ErrExportOutsideDir
	}
	base := filepath.Clean(dir)
	p := name
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	rel, err := filepath.Rel(base, filepath.Clean(p))
	if err != nil || rel == "." || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", ErrExportOutsideDir
	}
	return rel, nil
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var validTiers = map[string]bool{TierProbation: true, TierStandard: true, TierSuspended: true, TierRevoked: true}

// checkInstance refuses an exported instance whose fields are outside the closed sets the relay writes.
func checkInstance(e *ExportedInst, maxDevices int) error {
	switch {
	case !uuidV4.MatchString(e.ID):
		return fmt.Errorf("instance id %q is not a UUIDv4", e.ID)
	case len(e.PublicKey) != 32:
		return errors.New("instance key is not 32 bytes")
	case !validTiers[e.Tier]:
		return fmt.Errorf("unknown tier %q", e.Tier)
	case e.Reason != "" && !Reasons[e.Reason]:
		return fmt.Errorf("unknown reason %q", e.Reason)
	case e.DeviceLimit < 1 || e.DeviceLimit > maxDevices:
		return fmt.Errorf("device limit %d outside 1 to %d", e.DeviceLimit, maxDevices)
	}
	return nil
}

// Import loads a verified export, skipping ids or keys that already exist. Any instance outside the closed
// sets makes the whole import fail. It returns the number of instances imported.
func (s *Store) Import(ex *Export, today, maxDevices int) (int, error) {
	for i := range ex.Instances {
		if err := checkInstance(&ex.Instances[i], maxDevices); err != nil {
			return 0, err
		}
	}
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
		if ids[e.ID] || keys[string(e.PublicKey)] {
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
	return n, s.importBlocks(ex, today)
}

func (s *Store) importBlocks(ex *Export, today int) error {
	sets := []struct {
		blocks []ExportedBlock
		reason string
		write  func(tx *bolt.Tx, k []byte, day int) error
	}{
		{ex.BlockedPairs, ReasonDeviceOptOut, func(tx *bolt.Tx, k []byte, day int) error { return put(tx, bBlockedPairs, k, PairBlock{Day: day}) }},
		{ex.BlockedTokens, ReasonOperatorBlock, func(tx *bolt.Tx, k []byte, day int) error {
			return tx.Bucket(bBlockedTokens).Put(k, []byte(strconv.Itoa(day)))
		}},
		{ex.OptOutPins, ReasonOptOutPin, func(tx *bolt.Tx, k []byte, day int) error { return put(tx, bOptOutPins, k, OptOutPin{Day: day}) }},
	}
	return s.update(func(tx *bolt.Tx) error {
		for _, set := range sets {
			for _, b := range set.blocks {
				k, err := hex.DecodeString(b.Pair)
				exp, derr := ParseDayString(b.ExpiresDay)
				if err != nil || len(k) != sha256.Size || derr != nil || b.Reason != set.reason {
					return fmt.Errorf("malformed %s entry in the registry export", set.reason) // the whole import fails
				}
				if exp < today {
					continue // expired: dropped, as on export
				}
				if err := set.write(tx, k, exp-RetainBlocks); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
