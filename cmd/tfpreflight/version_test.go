package main

import (
	"fmt"
	"testing"
)

func TestCoverageGaps(t *testing.T) {
	for _, tc := range []struct {
		versions []string
		want     string
	}{
		{[]string{"5.98.0", "5.99.1", "5.100.0", "6.17.0", "6.18.0"}, "[[5.100.0 6.17.0]]"},
		{[]string{"6.22.0", "6.22.1", "6.23.0", "6.57.1"}, "[[6.23.0 6.57.1]]"},
		{[]string{"5.100.0", "6.0.0", "6.1.0"}, "[]"},
		{[]string{"6.64.0"}, "[]"},
	} {
		if got := fmt.Sprint(coverageGaps(tc.versions)); got != tc.want {
			t.Errorf("coverageGaps(%v) = %s, want %s", tc.versions, got, tc.want)
		}
	}
}
