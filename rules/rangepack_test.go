package rules

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"6.9.0", "6.10.0", -1}, {"6.10.0", "6.9.0", 1}, {"5.100.0", "6.0.0", -1}, {"6.64.0", "6.64.0", 0}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d", c.a, c.b, got)
		}
	}
}
