package notice

import (
	"strings"
	"testing"
	"time"
)

func TestSecurityTxtCurrent(t *testing.T) {
	for _, line := range strings.Split(SecurityTxt, "\n") {
		if v, ok := strings.CutPrefix(line, "Expires: "); ok {
			exp, err := time.Parse(time.RFC3339, v)
			if err != nil {
				t.Fatal(err)
			}
			if left := time.Until(exp); left < 30*24*time.Hour || left > 367*24*time.Hour {
				t.Fatalf("security.txt Expires %s: renew it (RFC 9116 wants at most a year ahead)", v)
			}
			return
		}
	}
	t.Fatal("no Expires field")
}
