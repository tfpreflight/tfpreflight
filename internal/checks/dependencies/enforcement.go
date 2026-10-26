package dependencies

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// EnforcementFor loads the enforcement knowledge for a provider version. With no
// pack, or one that does not load, the knowledge is empty and nothing blocks:
// the safe direction.
func EnforcementFor(providerVersion string) (*EnforcementKnowledge, []string) {
	data, err := packs.ReadFile("aws/dependency/enforcement-" + providerVersion + ".json")
	if err != nil {
		return EmptyEnforcement(), nil
	}
	knowledge, problems, err := LoadEnforcement(data, providerVersion)
	if err != nil {
		return EmptyEnforcement(), []string{err.Error()}
	}
	return knowledge, problems
}

// EnforcementStatus is what AWS was observed to do when a referenced target was
// absent and the create ran.
//
// That a value reaches a create request says nothing about whether AWS refuses
// the create without it: AppConfig accepts an environment whose monitor names a
// role that does not exist, and CloudFront refuses a continuous deployment
// policy whether or not it exists. Only observation can say.
type EnforcementStatus string

const (
	// EnforcementUnobserved is the default: nothing observed, never blocks.
	EnforcementUnobserved EnforcementStatus = "unobserved"
	// EnforcementMatched means the create failed because the referenced target
	// was absent.
	EnforcementMatched EnforcementStatus = "matched"
	// EnforcementNotRequired means the create succeeded with the target absent:
	// the reference is real but does not block a create.
	EnforcementNotRequired EnforcementStatus = "not_required_at_create"
	// EnforcementAttributeRejected means the create failed over the attribute
	// itself, whatever it held, which says nothing about the target.
	EnforcementAttributeRejected EnforcementStatus = "attribute_rejected"
	// EnforcementInconclusive means the observations did not settle the
	// question, or disagree.
	EnforcementInconclusive EnforcementStatus = "inconclusive"
)

// Blocks reports whether the status may make a finding blocking.
func (s EnforcementStatus) Blocks() bool { return s == EnforcementMatched }

// EnforcementState is how far an observation has been reviewed.
type EnforcementState string

const (
	// StateObserved is an observation not yet trusted to block.
	StateObserved EnforcementState = "observed"
	// StateSupported is an observation reviewed and accepted as grounds to
	// block.
	StateSupported EnforcementState = "supported"
)

// EnforcementStrength is how directly the failure identified the referenced
// target.
type EnforcementStrength string

const (
	// StrengthExact means AWS named the referenced value or object.
	StrengthExact EnforcementStrength = "exact"
	// StrengthIndirect means AWS described the failure in other terms, such as a
	// role that cannot be assumed.
	StrengthIndirect EnforcementStrength = "indirect"
)

// EnforcementClaim is one observation of what AWS did.
type EnforcementClaim struct {
	Fingerprint EnforcementFingerprint `json:"fingerprint"`
	Status      EnforcementStatus      `json:"status"`
	State       EnforcementState       `json:"state"`
	Strength    EnforcementStrength    `json:"strength,omitempty"`
	// Observation names the record this claim came from.
	Observation string `json:"observation"`
	// AWSError is the error AWS returned, which a blocking finding cites.
	AWSError string `json:"aws_error,omitempty"`
	Note     string `json:"note,omitempty"`
}

// EnforcementPack is the enforcement knowledge for one provider version.
type EnforcementPack struct {
	Provider        string             `json:"provider"`
	ProviderVersion string             `json:"provider_version"`
	Claims          []EnforcementClaim `json:"claims"`
}

// EnforcementKnowledge answers what AWS was observed to do. It makes no network
// call.
type EnforcementKnowledge struct {
	byKey map[string]EnforcementStatus
	claim map[string]EnforcementClaim
}

// EmptyEnforcement is knowledge with no observations: nothing blocks.
func EmptyEnforcement() *EnforcementKnowledge {
	return &EnforcementKnowledge{byKey: map[string]EnforcementStatus{}, claim: map[string]EnforcementClaim{}}
}

// LoadEnforcement reads an enforcement pack and returns every problem in it, so
// a malformed or conflicting pack cannot block in silence. Disagreeing
// observations of one fingerprint are inconclusive, which never blocks.
func LoadEnforcement(data []byte, providerVersion string) (*EnforcementKnowledge, []string, error) {
	var pack EnforcementPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return EmptyEnforcement(), nil, fmt.Errorf("enforcement pack is not readable: %w", err)
	}
	if pack.ProviderVersion != providerVersion {
		return EmptyEnforcement(), nil, fmt.Errorf("enforcement pack is for provider %s, not %s", pack.ProviderVersion, providerVersion)
	}
	knowledge := EmptyEnforcement()
	var problems []string
	statuses := map[string]map[EnforcementStatus]bool{}
	for index, claim := range pack.Claims {
		if problem := claimProblem(claim, providerVersion); problem != "" {
			problems = append(problems, fmt.Sprintf("claim %d (%s.%s)", index, claim.Fingerprint.Resource, claim.Fingerprint.Attribute)+": "+problem)
			continue
		}
		key := claim.Fingerprint.Key()
		if statuses[key] == nil {
			statuses[key] = map[EnforcementStatus]bool{}
		}
		statuses[key][claim.Status] = true
		// Only a supported claim can decide; an observed one is recorded and
		// ignored.
		if claim.State == StateSupported {
			knowledge.claim[key] = claim
		}
	}
	problems = append(problems, knowledge.settle(statuses)...)
	return knowledge, problems, nil
}

func claimProblem(claim EnforcementClaim, providerVersion string) string {
	switch claim.Status {
	case EnforcementMatched, EnforcementNotRequired, EnforcementAttributeRejected, EnforcementInconclusive:
	default:
		return "unknown status " + string(claim.Status)
	}
	switch claim.State {
	case StateObserved, StateSupported:
	default:
		return "unknown state " + string(claim.State)
	}
	if claim.Fingerprint.ProviderVersion != providerVersion {
		return "fingerprint names provider " + claim.Fingerprint.ProviderVersion
	}
	if !claim.Fingerprint.Complete() {
		return "fingerprint is incomplete"
	}
	if claim.Observation == "" {
		return "no observation is named"
	}
	return ""
}

// settle records each fingerprint's status. A fingerprint observed with more
// than one status is inconclusive, loses its supported claim, and is reported.
func (k *EnforcementKnowledge) settle(statuses map[string]map[EnforcementStatus]bool) []string {
	var problems []string
	for key, observed := range statuses {
		if len(observed) > 1 {
			kinds := make([]string, 0, len(observed))
			for status := range observed {
				kinds = append(kinds, string(status))
			}
			sort.Strings(kinds)
			problems = append(problems, "conflicting observations for "+key+": "+strings.Join(kinds, ", "))
			k.byKey[key] = EnforcementInconclusive
			delete(k.claim, key)
			continue
		}
		for status := range observed {
			if _, supported := k.claim[key]; supported {
				k.byKey[key] = status
			}
		}
	}
	return problems
}

// Status is what was observed for a rule's semantics.
func (k *EnforcementKnowledge) Status(fingerprint EnforcementFingerprint) (EnforcementStatus, EnforcementClaim) {
	if k == nil {
		return EnforcementUnobserved, EnforcementClaim{}
	}
	key := fingerprint.Key()
	status, ok := k.byKey[key]
	if !ok {
		return EnforcementUnobserved, EnforcementClaim{}
	}
	return status, k.claim[key]
}

// Supported counts the fingerprints that may block.
func (k *EnforcementKnowledge) Supported() int {
	if k == nil {
		return 0
	}
	count := 0
	for _, status := range k.byKey {
		if status.Blocks() {
			count++
		}
	}
	return count
}

// BlockingDecision is the one place a dependency finding is judged blocking.
// Every condition must hold, and each closes a way to block without proof:
//   - the reference is missing, not unknown: AccessDenied or a transport
//     failure is not an answer;
//   - the lookup can prove absence at all;
//   - the value comes from outside this plan;
//   - the create call is settled, since a resource choosing between create
//     operations may not make the observed one;
//   - the semantics match a supported observation exactly, so evidence about
//     one operation never speaks for another.
type BlockingDecision struct {
	Blocking bool
	Reason   string
	// Claim is the supported observation behind a block; empty otherwise.
	Claim EnforcementClaim
}

// BlockingInput is everything the gate is allowed to consider.
type BlockingInput struct {
	Rule ExistenceRule
	// Verdict is the engine's conclusion for the rule. Only a violation can
	// block.
	Verdict         string
	ProviderVersion string
	SamePlan        bool
	// ScopeResolved reports that the reference was inspected in the account and
	// region it names.
	ScopeResolved bool
}

// Decide applies the blocking gate.
func (k *EnforcementKnowledge) Decide(input BlockingInput) BlockingDecision {
	switch {
	case input.SamePlan:
		return BlockingDecision{Reason: "the target is produced by this plan, so it is not inspected"}
	case input.Verdict != VerdictViolation:
		return BlockingDecision{Reason: "the target was not proven missing"}
	case !input.ScopeResolved:
		return BlockingDecision{Reason: "the reference names an account or region this inspection did not resolve"}
	case !input.Rule.Lookup.ProvesAbsence():
		return BlockingDecision{Reason: "the lookup cannot prove absence, so a missing verdict is not decisive"}
	case input.Rule.CreateOperationAlternatives:
		return BlockingDecision{Reason: "the value reaches this member through more than one create operation, and which one this plan will make is not settled"}
	}
	fingerprint := input.Rule.Fingerprint(input.ProviderVersion)
	if !fingerprint.Complete() {
		return BlockingDecision{Reason: "the rule does not record complete create semantics to match evidence against"}
	}
	status, claim := k.Status(fingerprint)
	switch status {
	case EnforcementMatched:
		return BlockingDecision{
			Blocking: true, Claim: claim,
			Reason: "AWS was observed to reject " + fingerprint.CreateService + ":" + fingerprint.CreateOperation + " when this reference's target was absent",
		}
	case EnforcementNotRequired:
		return BlockingDecision{Reason: "AWS was observed to accept this create with the target absent"}
	case EnforcementAttributeRejected:
		return BlockingDecision{Reason: "AWS rejects this attribute during create whatever it holds, so absence of the target is not the cause"}
	case EnforcementInconclusive:
		return BlockingDecision{Reason: "observations of this create path disagree"}
	default:
		return BlockingDecision{Reason: "create-time enforcement has not been verified for this reference"}
	}
}
