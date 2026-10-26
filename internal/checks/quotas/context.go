package quotas

import "github.com/tfpreflight/tfpreflight/rules/model"

// UsageContext is the plan facts a generated counter may need. Today's counters
// are scoped to the account and region and need none.
type UsageContext struct {
	Resource string
	Changes  []model.PlannedChange
	Region   string
}
