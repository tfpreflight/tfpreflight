package quotas

import (
	"fmt"

	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// VCPUResolver reports an instance type's vCPU count, as DescribeInstanceTypes
// states it; it is never derived from the type's name.
type VCPUResolver interface {
	VCPUCount(instanceType string) (int32, bool, error)
}

// PlannedConsumption computes how much of a quota the planned changes add during
// apply. Deletions do not offset creations: a create_before_destroy replacement
// holds both at once, and the quota sees the peak. Counting a deletion as
// headroom would predict success for an apply that fails at its busiest moment.
func PlannedConsumption(changes []model.PlannedChange, rule Rule, vcpu VCPUResolver) Measurement {
	total := 0.0
	for _, change := range changes {
		if change.ResourceType != rule.Resource {
			continue
		}
		units, measurement := changeUnits(change, rule, vcpu)
		if !measurement.Known {
			return measurement
		}
		total += units
	}
	return Known(total)
}

func changeUnits(change model.PlannedChange, rule Rule, vcpu VCPUResolver) (float64, Measurement) {
	switch change.Action {
	case model.ActionCreate:
	case model.ActionReplace:
		// A replacement requests the new resource while the old one may still
		// exist, so it counts as an addition.
	default:
		// Deletes and in-place updates add nothing, and a delete frees nothing:
		// the apply may need the room before it happens.
		return 0, Known(0)
	}

	switch rule.Consumption.Type {
	case rules.ConsumptionResourceCount:
		units := rule.Consumption.Units
		if units == 0 {
			units = 1
		}
		return units, Known(units)
	case rules.ConsumptionVCPU:
		instanceType, ok := plannedString(change, rule.Consumption.Field)
		if !ok {
			return 0, Unknown(fmt.Sprintf("%s is not known until apply, so its vCPU count cannot be determined", rule.Consumption.Field))
		}
		if vcpu == nil {
			return 0, Unknown("no instance type resolver is available to convert " + instanceType + " into vCPUs")
		}
		count, found, err := vcpu.VCPUCount(instanceType)
		if err != nil {
			return 0, Unknown("AWS could not be asked how many vCPUs " + instanceType + " has: " + err.Error())
		}
		if !found {
			return 0, Unknown("AWS reported no vCPU count for instance type " + instanceType)
		}
		return float64(count), Known(float64(count))
	case rules.ConsumptionAttribute:
		value, ok := plannedNumber(change, rule.Consumption.Field)
		if !ok {
			return 0, Unknown(fmt.Sprintf("%s is not a known number in the plan", rule.Consumption.Field))
		}
		return value, Known(value)
	default:
		return 0, Unknown("tfpreflight does not know how much of this quota the resource consumes")
	}
}

// plannedString reads a string attribute the plan knows. A value not known until
// apply is unknown, not guessed.
func plannedString(change model.PlannedChange, field string) (string, bool) {
	if attributeUnknown(change.AfterUnknown, field) {
		return "", false
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := after[field].(string)
	return value, ok && value != ""
}

func plannedNumber(change model.PlannedChange, field string) (float64, bool) {
	if attributeUnknown(change.AfterUnknown, field) {
		return 0, false
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		return 0, false
	}
	switch value := after[field].(type) {
	case float64:
		return value, true
	case int:
		return float64(value), true
	default:
		return 0, false
	}
}

func attributeUnknown(afterUnknown any, field string) bool {
	unknown, ok := afterUnknown.(map[string]any)
	if !ok {
		return false
	}
	switch value := unknown[field].(type) {
	case bool:
		return value
	case map[string]any, []any:
		return true
	default:
		return false
	}
}
