package packs

// AWS returns the AWS provider versions the active pack set covers, oldest
// first.
func AWS() ([]string, error) {
	set, err := Active()
	if err != nil {
		return nil, err
	}
	return set.Versions(), nil
}
