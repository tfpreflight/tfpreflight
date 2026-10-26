package rules

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// Kinds of value a configuration can reference a target by.
const (
	// KeyID is the target's own Terraform id.
	KeyID = "id"
	// KeyARN is the target's ARN.
	KeyARN = "arn"
	// KeyName is the target's name.
	KeyName = "name"
)

// How a referenced value becomes the value a lookup takes.
const (
	// NormalizationNone means the lookup takes the referenced value itself.
	NormalizationNone = "none"
	// NormalizationARNComponent reads the value out of the ARN's resource
	// component, as AWS's ARN format describes it.
	NormalizationARNComponent = "arn_component"
	// NormalizationARNLastSegment also drops the path AWS says the component
	// carries: a role ARN holds RoleNameWithPath, while GetRole takes the name.
	NormalizationARNLastSegment = "arn_component_last_segment"
)

// ReferenceKey is what a configuration references a target by, and how that
// value reaches the lookup. The value is passed through unchanged, or read out
// of an ARN exactly where AWS's grammar puts it. Anything that does not match is
// unknown, never missing.
type ReferenceKey struct {
	Kind          string `json:"kind"`
	Normalization string `json:"normalization"`
	// ARNService is the service an ARN must belong to, and ARNPrefix the text
	// its resource component must begin with.
	ARNService string `json:"arn_service,omitempty"`
	ARNPrefix  string `json:"arn_prefix,omitempty"`
	ARNFormat  string `json:"arn_format,omitempty"`
	// Evidence is where the semantics came from.
	Evidence string `json:"evidence,omitempty"`
}

// canonical is the key of an older rule without key semantics: the target's own
// id, taken as it is.
func (k ReferenceKey) canonical() ReferenceKey {
	if k.Kind == "" {
		return ReferenceKey{Kind: KeyID, Normalization: NormalizationNone}
	}
	return k
}

// LookupValue converts a referenced value into the value the lookup takes, or
// says why it cannot. A refusal is partial coverage, never absence.
func (k ReferenceKey) LookupValue(referenced string) (string, string) {
	key := k.canonical()
	if key.Normalization == "" || key.Normalization == NormalizationNone {
		return referenced, ""
	}
	component, refusal := key.arnComponent(referenced)
	if refusal != "" {
		return "", refusal
	}
	return key.normalize(component)
}

// arnComponent is the part of an ARN after the key's resource prefix, or a
// refusal saying why the reference is not such an ARN.
func (k ReferenceKey) arnComponent(referenced string) (string, string) {
	if !arn.IsARN(referenced) {
		return "", "the reference does not hold an ARN"
	}
	parsed, err := arn.Parse(referenced)
	if err != nil {
		return "", "the reference does not hold a well-formed ARN"
	}
	if k.ARNService != "" && parsed.Service != k.ARNService {
		return "", "the ARN belongs to " + parsed.Service + ", not " + k.ARNService
	}
	component, found := strings.CutPrefix(parsed.Resource, k.ARNPrefix)
	if !found || component == "" {
		return "", "the ARN does not match the published format " + k.ARNFormat
	}
	return component, ""
}

func (k ReferenceKey) normalize(component string) (string, string) {
	switch k.Normalization {
	case NormalizationARNLastSegment:
		// AWS says this component carries a path; the value is its last part.
		if index := strings.LastIndex(component, "/"); index >= 0 {
			component = component[index+1:]
		}
		if component == "" {
			return "", "the ARN does not match the published format " + k.ARNFormat
		}
		return component, ""
	default:
		// Anything further in the component, such as a version, alias or sub-
		// resource, is a shape the grammar does not describe.
		if separator := k.separator(); separator != "" && strings.Contains(component, separator) {
			return "", "the ARN carries more than the published format " + k.ARNFormat + " describes"
		}
		if strings.ContainsAny(component, "/:") {
			return "", "the ARN carries more than the published format " + k.ARNFormat + " describes"
		}
		return component, ""
	}
}

func (k ReferenceKey) separator() string {
	if k.ARNPrefix == "" {
		return ""
	}
	return k.ARNPrefix[len(k.ARNPrefix)-1:]
}
