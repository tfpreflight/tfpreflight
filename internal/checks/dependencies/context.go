package dependencies

import "encoding/json"

// How the default AWS provider block states its region in the plan.
const (
	// RegionLiteral is a value Terraform evaluated without any input.
	RegionLiteral = "literal"
	// RegionAbsent means the provider block sets no region, so the provider
	// takes it from the environment.
	RegionAbsent = "absent"
	// RegionReferences means the expression reads other values. The plan records
	// which, but not how they combine: var.region and format("%s", var.region)
	// look the same.
	RegionReferences = "references"
	// RegionOther is an expression the plan records with neither a value nor
	// references, such as a function of literals.
	RegionOther = "other"
)

// ProviderContext is what the plan proves about the default provider's scope. It
// describes the region without deciding it: that needs the environment and the
// provider block's source, which the AWS context resolver holds.
type ProviderContext struct {
	// Region is set only when RegionKind is RegionLiteral.
	Region           string
	RegionKind       string
	RegionReferences []string
	// Variables are the root module input values the plan recorded.
	Variables       map[string]any
	Profile         string
	AllowedAccounts []string
	// AssumeRole is the role the provider assumes, if any.
	AssumeRole *AssumeRole
	// Reason is set when the provider configuration rules out inspecting with
	// tfpreflight's credentials at all.
	Reason string
}

// AssumeRole is the provider block's assume_role, as the plan records it.
type AssumeRole struct {
	// RoleARN is set when the plan records it as a literal.
	RoleARN string
	// RoleARNReferences is what it references otherwise, such as var.role.
	RoleARNReferences []string
	// ExternalID is a literal external ID, if one is set.
	ExternalID string
	// Unresolved is why tfpreflight cannot assume the role as the provider
	// would.
	Unresolved string
	// SessionPolicy is set when a session policy narrows the role; the role
	// simulated alone is then at least as permissive as the session.
	SessionPolicy bool
}

func assumeRole(raw json.RawMessage) *AssumeRole {
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) != 1 {
		return &AssumeRole{Unresolved: "the provider's assume_role block could not be read"}
	}
	block := blocks[0]
	role := &AssumeRole{}
	literal := func(name string) (string, []string, bool) {
		var e expression
		if json.Unmarshal(block[name], &e) != nil {
			return "", nil, false
		}
		if text, ok := e.ConstantValue.(string); ok && text != "" {
			return text, nil, true
		}
		return "", e.References, false
	}
	if _, ok := block["role_arn"]; !ok {
		role.Unresolved = "the provider's assume_role names no role_arn"
		return role
	}
	if value, references, ok := literal("role_arn"); ok {
		role.RoleARN = value
	} else if len(references) > 0 {
		role.RoleARNReferences = references
	} else {
		role.Unresolved = "the provider's assume_role.role_arn is an expression tfpreflight cannot evaluate"
	}
	if _, ok := block["external_id"]; ok {
		if value, _, ok := literal("external_id"); ok {
			role.ExternalID = value
		} else {
			role.Unresolved = "the provider's assume_role.external_id is not a literal"
		}
	}
	for _, name := range []string{"policy", "policy_arns"} {
		if _, ok := block[name]; ok {
			role.SessionPolicy = true
		}
	}
	return role
}

func providerContext(doc planDocument) ProviderContext {
	provider := ProviderContext{Variables: map[string]any{}}
	for name, variable := range doc.Variables {
		provider.Variables[name] = variable.Value
	}
	p, ok := doc.Configuration.Providers[DefaultProvider]
	if !ok {
		// No provider block: the provider configures itself from the
		// environment, region included.
		provider.RegionKind = RegionAbsent
		return provider
	}
	if name := unsupportedProviderSetting(p.Expressions); name != "" {
		provider.Reason = "provider context requires unsupported configuration: " + name
		return provider
	}
	if raw, ok := p.Expressions["assume_role"]; ok {
		provider.AssumeRole = assumeRole(raw)
	}
	provider.RegionKind, provider.Region, provider.RegionReferences = providerRegion(p.Expressions)
	if raw, ok := p.Expressions["profile"]; ok {
		v, known := constantExpression(raw)
		provider.Profile, _ = v.(string)
		if !known || provider.Profile == "" {
			provider.Reason = "provider profile is unresolved"
			return provider
		}
	}
	if raw, ok := p.Expressions["allowed_account_ids"]; ok {
		var known bool
		provider.AllowedAccounts, known = allowedAccounts(raw)
		if !known {
			provider.Reason = "provider account restriction is unresolved"
			return provider
		}
	}
	return provider
}

// unsupportedProviderSetting names the first provider argument tfpreflight
// cannot reproduce, or "". Another credential chain, endpoint or partition
// cannot be reconstructed from the inspection defaults; assume_role can, by
// assuming the same role.
func unsupportedProviderSetting(expressions map[string]json.RawMessage) string {
	for _, name := range []string{"assume_role_with_web_identity", "access_key", "secret_key", "token", "shared_credentials_files", "shared_config_files", "endpoints", "forbidden_account_ids"} {
		if _, ok := expressions[name]; ok {
			return name
		}
	}
	return ""
}

// constantExpression returns an expression's value when the plan records it as a
// constant. A reference list proves no direct use: format(..., var.region) has
// the same list as var.region.
func constantExpression(raw json.RawMessage) (any, bool) {
	var e expression
	if json.Unmarshal(raw, &e) != nil {
		return nil, false
	}
	if e.ConstantValue != nil {
		return e.ConstantValue, true
	}
	return nil, false
}

func providerRegion(expressions map[string]json.RawMessage) (kind, region string, references []string) {
	raw, ok := expressions["region"]
	if !ok {
		return RegionAbsent, "", nil
	}
	var e expression
	_ = json.Unmarshal(raw, &e)
	v, known := constantExpression(raw)
	switch literal, _ := v.(string); {
	case known && literal != "":
		return RegionLiteral, literal, nil
	case len(e.References) > 0:
		return RegionReferences, "", e.References
	default:
		return RegionOther, "", nil
	}
}

// allowedAccounts reads allowed_account_ids. known is false unless it is a
// constant list of strings.
func allowedAccounts(raw json.RawMessage) (accounts []string, known bool) {
	v, known := constantExpression(raw)
	values, isList := v.([]any)
	if !known || !isList {
		return nil, false
	}
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			return accounts, false
		}
		accounts = append(accounts, s)
	}
	return accounts, true
}
