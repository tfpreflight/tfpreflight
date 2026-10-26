package permissions

import (
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// noResourcePolicies are the services whose resources take no resource-based
// policy that could allow a call ("Resource-based policies: No" in AWS's
// "AWS services that work with IAM"). A role's trust policy allows only
// sts:AssumeRole, so iam is one of them.
var noResourcePolicies = map[string]bool{
	"acm": true, "autoscaling": true, "cloudfront": true, "cloudwatch": true,
	"ec2": true, "ecs": true, "eks": true, "elasticache": true,
	"elasticloadbalancing": true, "iam": true, "rds": true, "route53": true,
}

// resourcePolicyMayAllow says why a resource-based policy, which the
// simulation does not read, could still allow a call IAM denies implicitly, or
// "" when none could:
//   - the action is authorized only against "*", so no resource holds a policy;
//   - the action's service takes no resource-based policies; or
//   - the call creates the planned resource, which has no policy until it exists.
//
// Any other implicit deny, such as one on an existing bucket or key, or on a
// resource being created that its parent's policy covers, may be allowed.
func resourcePolicyMayAllow(requirement plannedPermission, target target) string {
	service, action, _ := strings.Cut(requirement.operation.Permission, ":")
	switch {
	case target.ARN == "*":
		return ""
	case noResourcePolicies[strings.ToLower(service)]:
		return ""
	case target.Own && requirement.change.Action == model.ActionCreate && strings.HasPrefix(action, "Create"):
		return ""
	}
	return "IAM denies this only implicitly. A resource-based policy on " + target.ARN +
		", such as a bucket or key policy, could still allow it, and tfpreflight does not read resource-based policies."
}
