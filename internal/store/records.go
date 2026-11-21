package store

import (
	"encoding/hex"
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// Instance is a registered HealthLog server.
type Instance struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"publicKey"`
	Tier             string `json:"tier"`
	Reason           string `json:"reason,omitempty"`
	CreatedDay       int    `json:"createdDay"`
	LastSeenWeek     int    `json:"lastSeenWeek"`
	DeviceLimit      int    `json:"deviceLimit"`
	FirstDeliveryDay int    `json:"firstDeliveryDay,omitempty"`
	RotatedDay       int    `json:"rotatedDay,omitempty"`
	QuietSinceDay    int    `json:"quietSinceDay,omitempty"`
	LastPushDay      int    `json:"lastPushDay,omitempty"` // day of the last accepted push, for usage counts
	ReasonDay        int    `json:"reasonDay,omitempty"`   // day of the suspension or revocation
	Client           string `json:"client,omitempty"`
}

// Binding binds a device token (by MAC) to one instance with a device-held key.
type Binding struct {
	InstanceID     string `json:"instanceId"`
	KeyHash        []byte `json:"keyHash"`
	Seq            int64  `json:"seq"`
	Env            string `json:"env"`
	State          string `json:"state"`
	BoundDay       int    `json:"boundDay"`
	LastUsedWeek   int    `json:"lastUsedWeek"`
	LastSuccessDay int    `json:"lastSuccessDay,omitempty"`
	SoftInvalidDay int    `json:"softInvalidDay,omitempty"`
	ConsentVersion string `json:"consentVersion"`
	ConsentDay     string `json:"consentDay"`
	AlertsToday    int    `json:"alertsToday,omitempty"`
	AlertsDay      int    `json:"alertsDay,omitempty"`
}

// PutInstance writes an instance and its key index.
func (s *Store) PutInstance(in *Instance) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := put(tx, bInstances, []byte(in.ID), in); err != nil {
			return err
		}
		return tx.Bucket(bInstanceKeys).Put([]byte(hex.EncodeToString(in.PublicKey)), []byte(in.ID))
	})
}

// ReplaceInstanceKey moves the key index from old to the instance's new key.
func (s *Store) ReplaceInstanceKey(in *Instance, oldKey []byte) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bInstanceKeys).Delete([]byte(hex.EncodeToString(oldKey))); err != nil {
			return err
		}
		if err := put(tx, bInstances, []byte(in.ID), in); err != nil {
			return err
		}
		return tx.Bucket(bInstanceKeys).Put([]byte(hex.EncodeToString(in.PublicKey)), []byte(in.ID))
	})
}

// DeleteInstance removes an instance, its key index and all its bindings.
func (s *Store) DeleteInstance(id string) error {
	return s.update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bInstances).Get([]byte(id))
		if v != nil {
			var in Instance
			if json.Unmarshal(v, &in) == nil {
				_ = tx.Bucket(bInstanceKeys).Delete([]byte(hex.EncodeToString(in.PublicKey)))
			}
		}
		if err := tx.Bucket(bInstances).Delete([]byte(id)); err != nil {
			return err
		}
		return deleteBindingsOf(tx, id)
	})
}

func deleteBindingsOf(tx *bolt.Tx, id string) error {
	return deleteWhere(tx, bBindings, func(_, v []byte) bool {
		var b Binding
		return json.Unmarshal(v, &b) == nil && b.InstanceID == id
	})
}

// DeleteBindingsOf removes all bindings of an instance.
func (s *Store) DeleteBindingsOf(id string) error {
	return s.update(func(tx *bolt.Tx) error { return deleteBindingsOf(tx, id) })
}

// Instances returns all instances.
func (s *Store) Instances() ([]*Instance, error) {
	var out []*Instance
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bInstances).ForEach(func(_, v []byte) error {
			var in Instance
			if err := json.Unmarshal(v, &in); err != nil {
				return err
			}
			out = append(out, &in)
			return nil
		})
	})
	return out, err
}

// PutBinding writes a binding under its token MAC.
func (s *Store) PutBinding(mac []byte, b *Binding) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bBindings, mac, b) })
}

// DeleteBinding removes a binding.
func (s *Store) DeleteBinding(mac []byte) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBindings).Delete(mac) })
}

// RenameBinding moves a binding to a new MAC key (MAC key rotation).
func (s *Store) RenameBinding(oldMac, newMac []byte, b *Binding) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bBindings).Delete(oldMac); err != nil {
			return err
		}
		return put(tx, bBindings, newMac, b)
	})
}

// Bindings returns every binding keyed by the MAC as a string of raw bytes.
func (s *Store) Bindings() (map[string]*Binding, error) {
	out := map[string]*Binding{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bBindings).ForEach(func(k, v []byte) error {
			var b Binding
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			out[string(k)] = &b
			return nil
		})
	})
	return out, err
}
