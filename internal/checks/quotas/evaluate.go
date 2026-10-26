package quotas

import "fmt"

const (
	// VerdictExceeds means the plan is predicted to cross the limit.
	VerdictExceeds = "exceeds"
	// VerdictWithin means all three parts are known and the total fits.
	VerdictWithin = "within"
	// VerdictUnknown means a part could not be determined, so nothing is
	// claimed.
	VerdictUnknown = "unknown"
)

// Measurement is one part of the comparison: known with a value, or unknown with
// a reason. There is no zero default: a missing usage figure read as zero turns
// "we could not check" into "you have plenty of room".
type Measurement struct {
	Value  float64
	Known  bool
	Reason string
}

// Known is a determined measurement.
func Known(value float64) Measurement { return Measurement{Value: value, Known: true} }

// Unknown is an undetermined measurement and why.
func Unknown(reason string) Measurement { return Measurement{Reason: reason} }

// Decision is the result of comparing a plan with one quota.
type Decision struct {
	Verdict string
	Limit   Measurement
	Usage   Measurement
	Planned Measurement
	// Expected is the projected total, set only when every part is known.
	Expected float64
	// Reason names the missing part of an unknown verdict.
	Reason string
}

// Evaluate compares a quota's limit with current plus planned usage. Any unknown
// part makes the verdict unknown: assuming zero usage, or an unlimited quota,
// would report headroom that was never measured.
func Evaluate(limit, usage, planned Measurement) Decision {
	decision := Decision{Limit: limit, Usage: usage, Planned: planned}
	switch {
	case !limit.Known:
		decision.Verdict, decision.Reason = VerdictUnknown, "the quota limit is unknown: "+orUnstated(limit.Reason)
		return decision
	case !usage.Known:
		decision.Verdict, decision.Reason = VerdictUnknown, "current usage is unknown: "+orUnstated(usage.Reason)
		return decision
	case !planned.Known:
		decision.Verdict, decision.Reason = VerdictUnknown, "the plan's additional usage is unknown: "+orUnstated(planned.Reason)
		return decision
	}
	decision.Expected = usage.Value + planned.Value
	if decision.Expected > limit.Value {
		decision.Verdict = VerdictExceeds
		decision.Reason = fmt.Sprintf("current %g plus planned %g exceeds the limit of %g",
			usage.Value, planned.Value, limit.Value)
		return decision
	}
	decision.Verdict = VerdictWithin
	decision.Reason = fmt.Sprintf("current %g plus planned %g stays within the limit of %g",
		usage.Value, planned.Value, limit.Value)
	return decision
}

// Blocking reports whether the decision justifies a finding that the apply will
// fail.
func (d Decision) Blocking() bool { return d.Verdict == VerdictExceeds }

// Partial reports whether the check ran but could not conclude, which is
// reported as incomplete coverage rather than silence.
func (d Decision) Partial() bool { return d.Verdict == VerdictUnknown }

func orUnstated(reason string) string {
	if reason == "" {
		return "no reason recorded"
	}
	return reason
}
