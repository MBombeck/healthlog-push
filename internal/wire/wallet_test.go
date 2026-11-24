package wire

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseWalletSign(t *testing.T) {
	m := []byte(`{"pass.json":"00"}`)
	got, err := ParseWalletSign([]byte(`{"v":1,"manifest":"` + base64.RawURLEncoding.EncodeToString(m) + `"}`))
	if err != nil || !bytes.Equal(got, m) {
		t.Fatalf("%q %v", got, err)
	}
	long := base64.RawURLEncoding.EncodeToString(make([]byte, WalletManifestMax+1))
	for _, b := range []string{`{"v":2,"manifest":"e30"}`, `{"v":1,"manifest":""}`, `{"v":1,"manifest":"e30="}`, `{"v":1,"manifest":"e3+"}`,
		`{"v":1,"manifest":"` + long + `"}`, `{"v":1,"Manifest":"e30"}`, `{"v":1,"manifest":"e30","v":1}`, `{"v":1,"manifest":"!!"}`} {
		if _, err := ParseWalletSign([]byte(b)); err == nil {
			t.Errorf("accepted %.60s", b)
		}
	}
}

func TestParseWalletNotify(t *testing.T) {
	tok := strings.Repeat("ab", 32)
	items, toks, err := ParseWalletNotify([]byte(`{"items":[{"ref":"a-1_B","token":"` + tok + `"},{"ref":"b","token":"` + strings.ToUpper(tok) + `"}]}`))
	if err != nil || len(items) != 2 || len(toks[0]) != 32 || toks[1][0] != 0xab {
		t.Fatalf("%v %v", items, err)
	}
	many := `{"items":[` + strings.Repeat(`{"ref":"x","token":"`+tok+`"},`, WalletNotifyMax) + `{"ref":"y","token":"` + tok + `"}]}`
	for _, b := range []string{`{"items":[]}`, `{"items":[{"ref":"a","token":"` + tok + `0"}]}`, `{"items":[{"ref":"","token":"` + tok + `"}]}`,
		`{"items":[{"ref":"` + strings.Repeat("r", 65) + `","token":"` + tok + `"}]}`, `{"items":[{"ref":"a","token":"` + strings.Repeat("ab", 101) + `"}]}`,
		`{"items":[{"ref":"a","token":"` + tok + `","x":1}]}`, many, `{"items":[{"ref":"a","token":"zz` + tok[2:] + `"}]}`} {
		if _, _, err := ParseWalletNotify([]byte(b)); err == nil {
			t.Errorf("accepted %.80s", b)
		}
	}
}

func TestWalletRequestValidOp(t *testing.T) {
	ok := []*WalletRequest{{Op: WalletOpSign, Manifest: []byte("{}")}, {Op: WalletOpNotify, Tokens: [][]byte{{1}}}, {Op: WalletOpInfo}}
	bad := []*WalletRequest{{Op: "x"}, {Op: WalletOpSign}, {Op: WalletOpSign, Manifest: make([]byte, WalletManifestMax+1)},
		{Op: WalletOpSign, Manifest: []byte("{}"), Tokens: [][]byte{{1}}}, {Op: WalletOpNotify}, {Op: WalletOpNotify, Tokens: make([][]byte, WalletNotifyMax+1)},
		{Op: WalletOpInfo, Manifest: []byte("{}")}}
	for _, r := range ok {
		if !r.ValidOp() {
			t.Errorf("refused %+v", r)
		}
	}
	for _, r := range bad {
		if r.ValidOp() {
			t.Errorf("accepted %+v", r)
		}
	}
	if !ValidPassTypeID("pass.dev.healthlog.emergency") || ValidPassTypeID("dev.healthlog") || !ValidTeamID("ABCDE12345") || ValidTeamID("abc") {
		t.Fatal("identifier checks")
	}
}

func FuzzParseWalletSign(f *testing.F) {
	f.Add([]byte(`{"v":1,"manifest":"e30"}`))
	f.Add([]byte(`{"v":1,"manifest":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseWalletSign(b)
		if err == nil && (len(m) == 0 || len(m) > WalletManifestMax) {
			t.Fatalf("accepted a manifest of %d bytes", len(m))
		}
	})
}

func FuzzParseWalletNotify(f *testing.F) {
	f.Add([]byte(`{"items":[{"ref":"a","token":"` + strings.Repeat("ab", 32) + `"}]}`))
	f.Add([]byte(`{"items":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		items, toks, err := ParseWalletNotify(b)
		if err != nil {
			return
		}
		if len(items) == 0 || len(items) > WalletNotifyMax || len(toks) != len(items) {
			t.Fatal("accepted a bad item count")
		}
		for _, tk := range toks {
			if len(tk) < 32 || len(tk) > 100 {
				t.Fatalf("accepted a token of %d bytes", len(tk))
			}
		}
	})
}
