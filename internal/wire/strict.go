package wire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// exactKeys walks the JSON in b against the type of v and refuses what encoding/json would quietly accept:
// a key that matches a field only case-insensitively ("Token" for "token") and a key that appears twice in
// one object (where the last one would win). Together with DisallowUnknownFields this makes every body
// parse exactly one way.
func exactKeys(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	return walkJSON(dec, reflect.TypeOf(v))
}

func walkJSON(dec *json.Decoder, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return ErrInvalid
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	switch d {
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.More() {
			if err := walkJSON(dec, elem); err != nil {
				return err
			}
		}
	case '{':
		fields := structFields(t)
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			key, isStr := k.(string)
			if err != nil || !isStr || seen[key] {
				return ErrInvalid
			}
			seen[key] = true
			ft, known := fields[key]
			if fields != nil && !known {
				return ErrInvalid
			}
			if err := walkJSON(dec, ft); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	if err != nil {
		return ErrInvalid
	}
	return nil
}

// structFields maps the exact JSON names of a struct type to their field types; nil for anything else.
func structFields(t reflect.Type) map[string]reflect.Type {
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	m := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" || !f.IsExported() {
			continue
		}
		m[name] = f.Type
	}
	return m
}
