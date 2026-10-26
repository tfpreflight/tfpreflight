package dependencies

import (
	"encoding/json"
	"strings"
	"testing"
)

// rule builds a rule whose create semantics are complete, so the only thing a
// test varies is the component it is about.
func enforcementRule() ExistenceRule {
	return ExistenceRule{
		Resource: "aws_kinesis_stream_consumer", Attribute: "stream_arn",
		CreateService: "kinesis", CreateOperation: "RegisterStreamConsumer",
		Member: "StreamARN", TargetResource: "aws_kinesis_stream",
		CreateProvenance: "sdkv2_request_literal",
		Key:              ReferenceKey{Kind: KeyARN, Normalization: NormalizationARNComponent},
		Lookup:           Lookup{Service: "kinesis", Operation: "DescribeStreamSummary", Field: "StreamName", NotFoundCodes: []string{"ResourceNotFoundException"}},
	}
}

func pack(t *testing.T, claims ...EnforcementClaim) *EnforcementKnowledge {
	t.Helper()
	data, err := json.Marshal(EnforcementPack{Provider: "aws", ProviderVersion: "6.64.0", Claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, _, err := LoadEnforcement(data, "6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	return knowledge
}

func claim(rule ExistenceRule, status EnforcementStatus, state EnforcementState) EnforcementClaim {
	return EnforcementClaim{Fingerprint: rule.Fingerprint("6.64.0"), Status: status, State: state, Observation: "test.json"}
}

// The one path that may block: the target is proven missing, the lookup could
// have proven it, the create call is settled, and AWS was observed to reject
// that call for exactly these semantics.
func TestVerifiedEnforcementAndMissingTargetBlocks(t *testing.T) {
	rule := enforcementRule()
	knowledge := pack(t, claim(rule, EnforcementMatched, StateSupported))
	decision := knowledge.Decide(BlockingInput{Rule: rule, Verdict: VerdictViolation, ProviderVersion: "6.64.0", ScopeResolved: true})
	if !decision.Blocking {
		t.Fatalf("a verified missing reference did not block: %s", decision.Reason)
	}
	finding := missingFinding("aws_kinesis_stream_consumer.test", rule, "arn:aws:kinesis:us-east-1:1:stream/x", decision)
	if finding.Severity != "error" || finding.Confidence != "high" {
		t.Fatalf("finding severity/confidence = %s/%s, want error/high", finding.Severity, finding.Confidence)
	}
	if !strings.Contains(finding.Explanation, "kinesis:RegisterStreamConsumer") {
		t.Errorf("the finding does not say which call enforces the reference: %q", finding.Explanation)
	}
}

// Everything else stays non-blocking. Each row leaves one condition of
// BlockingDecision unmet.
func TestOnlyVerifiedEnforcementBlocks(t *testing.T) {
	for _, test := range []struct {
		name    string
		rule    func(ExistenceRule) ExistenceRule
		input   func(*BlockingInput)
		claims  []EnforcementClaim
		mention string
	}{
		{name: "no evidence at all", mention: "not been verified"},
		{
			name:   "evidence is only observed, not supported",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateObserved)}, mention: "not been verified",
		},
		{
			name:   "AWS accepted the create with the target absent",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementNotRequired, StateSupported)}, mention: "observed to accept",
		},
		{
			name:   "AWS rejects the attribute itself",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementAttributeRejected, StateSupported)}, mention: "whatever it holds",
		},
		{
			name:   "the target was not proven missing",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			input:  func(i *BlockingInput) { i.Verdict = VerdictPartial }, mention: "not proven missing",
		},
		{
			name:   "the target is produced by this plan",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			input:  func(i *BlockingInput) { i.SamePlan = true }, mention: "produced by this plan",
		},
		{
			name:   "the scope was not resolved",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			input:  func(i *BlockingInput) { i.ScopeResolved = false }, mention: "account or region",
		},
		{
			name:   "the lookup cannot prove absence",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			rule:   func(r ExistenceRule) ExistenceRule { r.Lookup.NotFoundCodes = nil; return r }, mention: "cannot prove absence",
		},
		{
			name:   "the create call is not settled",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			rule:   func(r ExistenceRule) ExistenceRule { r.CreateOperationAlternatives = true; return r }, mention: "more than one create operation",
		},
		{
			name:   "the rule records no create operation",
			claims: []EnforcementClaim{claim(enforcementRule(), EnforcementMatched, StateSupported)},
			rule:   func(r ExistenceRule) ExistenceRule { r.CreateOperation = ""; return r }, mention: "complete create semantics",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := enforcementRule()
			knowledge := pack(t, test.claims...)
			if test.rule != nil {
				rule = test.rule(rule)
			}
			input := BlockingInput{Rule: rule, Verdict: VerdictViolation, ProviderVersion: "6.64.0", ScopeResolved: true}
			if test.input != nil {
				test.input(&input)
			}
			decision := knowledge.Decide(input)
			if decision.Blocking {
				t.Fatalf("blocked when it should not have: %s", decision.Reason)
			}
			if !strings.Contains(decision.Reason, test.mention) {
				t.Errorf("reason = %q, want it to mention %q", decision.Reason, test.mention)
			}
			finding := missingFinding("x.y", rule, "id", decision)
			if finding.Severity != "warning" || finding.Confidence != "medium" {
				t.Errorf("a non-blocking finding was %s/%s", finding.Severity, finding.Confidence)
			}
		})
	}
}

// Evidence is tied to semantics, not to an attribute name. Changing any part of
// what AWS saw makes the old observation describe something else.
func TestChangingAnySemanticStopsBlocking(t *testing.T) {
	stored := claim(enforcementRule(), EnforcementMatched, StateSupported)
	knowledge := pack(t, stored)
	for name, mutate := range map[string]func(ExistenceRule) ExistenceRule{
		"a different create operation": func(r ExistenceRule) ExistenceRule { r.CreateOperation = "PutStreamConsumer"; return r },
		"a different service":          func(r ExistenceRule) ExistenceRule { r.CreateService = "kinesisvideo"; return r },
		"a different request member":   func(r ExistenceRule) ExistenceRule { r.Member = "Logging.StreamARN"; return r },
		"a different target type":      func(r ExistenceRule) ExistenceRule { r.TargetResource = "aws_kinesis_video_stream"; return r },
		"a different key kind":         func(r ExistenceRule) ExistenceRule { r.Key.Kind = KeyName; return r },
		"different normalization":      func(r ExistenceRule) ExistenceRule { r.Key.Normalization = NormalizationNone; return r },
		"a different provenance":       func(r ExistenceRule) ExistenceRule { r.CreateProvenance = "framework_model_mapping"; return r },
		"a different attribute":        func(r ExistenceRule) ExistenceRule { r.Attribute = "other_arn"; return r },
	} {
		t.Run(name, func(t *testing.T) {
			decision := knowledge.Decide(BlockingInput{Rule: mutate(enforcementRule()), Verdict: VerdictViolation, ProviderVersion: "6.64.0", ScopeResolved: true})
			if decision.Blocking {
				t.Fatalf("stale evidence still blocked after changing %s", name)
			}
		})
	}
	// A different provider version reads no evidence at all.
	if decision := knowledge.Decide(BlockingInput{Rule: enforcementRule(), Verdict: VerdictViolation, ProviderVersion: "6.65.0", ScopeResolved: true}); decision.Blocking {
		t.Fatal("evidence for 6.64.0 blocked a 6.65.0 evaluation")
	}
}

// Disagreeing observations are a reason not to block, not a vote to count.
func TestConflictingEvidenceDoesNotBlock(t *testing.T) {
	rule := enforcementRule()
	data, err := json.Marshal(EnforcementPack{Provider: "aws", ProviderVersion: "6.64.0", Claims: []EnforcementClaim{
		claim(rule, EnforcementMatched, StateSupported),
		claim(rule, EnforcementNotRequired, StateSupported),
	}})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, problems, err := LoadEnforcement(data, "6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Error("a conflict was not reported")
	}
	if decision := knowledge.Decide(BlockingInput{Rule: rule, Verdict: VerdictViolation, ProviderVersion: "6.64.0", ScopeResolved: true}); decision.Blocking {
		t.Fatal("conflicting evidence produced a blocker")
	}
}

// A malformed pack must not block, and must say what was wrong.
func TestInvalidEvidenceIsRejected(t *testing.T) {
	rule := enforcementRule()
	bad := []EnforcementClaim{
		{Fingerprint: rule.Fingerprint("6.64.0"), Status: "sometimes", State: StateSupported, Observation: "t.json"},
		{Fingerprint: rule.Fingerprint("6.64.0"), Status: EnforcementMatched, State: "trusted", Observation: "t.json"},
		{Fingerprint: rule.Fingerprint("6.64.0"), Status: EnforcementMatched, State: StateSupported},
		{Fingerprint: EnforcementFingerprint{ProviderVersion: "6.64.0", Resource: "aws_x"}, Status: EnforcementMatched, State: StateSupported, Observation: "t.json"},
	}
	for index, entry := range bad {
		data, err := json.Marshal(EnforcementPack{Provider: "aws", ProviderVersion: "6.64.0", Claims: []EnforcementClaim{entry}})
		if err != nil {
			t.Fatal(err)
		}
		knowledge, problems, err := LoadEnforcement(data, "6.64.0")
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) == 0 {
			t.Errorf("claim %d was accepted without complaint", index)
		}
		if knowledge.Supported() != 0 {
			t.Errorf("claim %d became supported", index)
		}
	}
	// A pack for another provider version is refused outright.
	data, _ := json.Marshal(EnforcementPack{Provider: "aws", ProviderVersion: "6.65.0"})
	if _, _, err := LoadEnforcement(data, "6.64.0"); err == nil {
		t.Error("a pack for another provider version was accepted")
	}
}

// The shipped pack must describe rules that actually exist, with no conflicts.
func TestShippedPackIsValid(t *testing.T) {
	knowledge, problems := EnforcementFor("6.64.0")
	if len(problems) != 0 {
		t.Fatalf("the shipped enforcement pack has problems: %v", problems)
	}
	// The blocking set is the release's sharpest claim, so its size is pinned.
	// It grows only when live verification adds evidence, which is a deliberate
	// change to this number and not a side effect of regenerating a pack.
	if knowledge.Supported() != 12 {
		t.Fatalf("the shipped pack supports %d blocking fingerprints, want 12", knowledge.Supported())
	}
}
