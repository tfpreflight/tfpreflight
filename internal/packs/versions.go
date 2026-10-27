package packs

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules"
)

// AWS returns the AWS provider versions the active pack set covers, oldest
// first.
func AWS() ([]string, error) {
	set, err := Active()
	if err != nil {
		return nil, err
	}
	return set.Versions(), nil
}

// NewerThanCovered returns a provider release newer than every version the
// active pack set covers: the minor release after the newest one. Tests use it
// for "a release these packs do not cover", which stays true when packs for a
// new provider release are added.
func NewerThanCovered() (string, error) {
	versions, err := AWS()
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", errors.New("the active pack set covers no AWS provider version")
	}
	newest := versions[0]
	for _, version := range versions[1:] {
		if rules.CompareVersions(version, newest) > 0 {
			newest = version
		}
	}
	parts := strings.Split(newest, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("covered version %q is not major.minor.patch", newest)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("covered version %q: %w", newest, err)
	}
	return parts[0] + "." + strconv.Itoa(minor+1) + ".0", nil
}
