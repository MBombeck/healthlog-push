package admin

import "testing"

func TestParse(t *testing.T) {
	ar, err := Parse([]string{"limits", "6f1c", "devices=80", "--for", "1h", "--level=planned"})
	if err != nil || ar.Cmd != "limits" || ar.Args[0] != "6f1c" || ar.Params["devices"] != "80" || ar.Params["for"] != "1h" || ar.Params["level"] != "planned" {
		t.Fatalf("%+v %v", ar, err)
	}
	if _, err := Parse([]string{"pause", "--for"}); err == nil {
		t.Fatal("flag without value accepted")
	}
}
