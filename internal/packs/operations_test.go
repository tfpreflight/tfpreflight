package packs

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
)

func operationIndex(t *testing.T) OperationPermissions {
	t.Helper()
	index, err := LoadOperationPermissions(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if index.Len() < 100 {
		t.Fatalf("indexed only %d operations", index.Len())
	}
	return index
}

func TestResolveUsesMetadataNotLowercasing(t *testing.T) {
	index := operationIndex(t)
	cases := []struct{ serviceID, operation, want string }{
		{"CloudWatch", "PutMetricAlarm", "cloudwatch:PutMetricAlarm"},
		{"EC2", "CreateVpc", "ec2:CreateVpc"},
		// Service ids whose IAM prefix is not a plain lowercase of the id.
		{"Elastic Beanstalk", "CreateEnvironment", "elasticbeanstalk:CreateEnvironment"},
		{"Route 53", "CreateHostedZone", "route53:CreateHostedZone"},
		{"EventBridge", "CreateEventBus", "events:CreateEventBus"},
		{"Location", "CreateMap", "geo:CreateMap"},
		{"Resource Groups", "CreateGroup", "resource-groups:CreateGroup"},
	}
	for _, c := range cases {
		got, ok := index.Resolve(c.serviceID, c.operation)
		if !ok || got != c.want {
			t.Fatalf("Resolve(%q, %q) = %q/%v, want %q", c.serviceID, c.operation, got, ok, c.want)
		}
	}
}

func TestResolveDisambiguatesSharedOperationNamesByService(t *testing.T) {
	index := operationIndex(t)
	// CreateApplication exists under several services; the SDK service id is
	// what selects the right one.
	got, ok := index.Resolve("Elastic Beanstalk", "CreateApplication")
	if !ok || got != "elasticbeanstalk:CreateApplication" {
		t.Fatalf("Resolve = %q/%v, want elasticbeanstalk:CreateApplication", got, ok)
	}
	if other, ok := index.Resolve("AppConfig", "CreateApplication"); !ok || other != "appconfig:CreateApplication" {
		t.Fatalf("Resolve = %q/%v, want appconfig:CreateApplication", other, ok)
	}
	// An unrelated service must not pick one of the candidates arbitrarily.
	if got, ok := index.Resolve("Mystery Service", "CreateApplication"); ok {
		t.Fatalf("an unknown service resolved to %q", got)
	}
}

func TestResolveRefusesUnknownOperationsAndServices(t *testing.T) {
	index := operationIndex(t)
	for _, c := range []struct{ serviceID, operation string }{
		{"CloudWatch", "DefinitelyNotAnOperation"},
		{"NotAService", "PutMetricAlarm"},
		{"", "PutMetricAlarm"},
		{"CloudWatch", ""},
	} {
		if got, ok := index.Resolve(c.serviceID, c.operation); ok {
			t.Fatalf("Resolve(%q, %q) resolved to %q", c.serviceID, c.operation, got)
		}
	}
}

func TestResolveRejectsSimilarityAndAmbiguity(t *testing.T) {
	index := operationIndex(t)
	for _, id := range []string{"eventbridge", "Events", "Cloud Watch", "EC", "ElasticLoadBalancingv2"} {
		if permission, ok := index.Resolve(id, "CreateEventBus"); ok {
			t.Fatalf("guessed %s", permission)
		}
	}
	pack := KnowledgePack{ServiceIdentities: map[string]rules.ServiceIdentity{"one": {ID: "Shared"}, "two": {ID: "Shared"}}, Resources: map[string]ResourceRule{"test": {Actions: map[string]ActionRule{"create": {Operations: []OperationRule{{Name: "Create", Service: "one", Permission: "one:Create"}, {Name: "Create", Service: "two", Permission: "two:Create"}}}}}}}
	if permission, ok := NewOperationPermissions(pack).Resolve("Shared", "Create"); ok {
		t.Fatalf("ambiguous permission %s", permission)
	}
}

func TestResolveELBV2WithAuthoritativeIdentity(t *testing.T) {
	pack, _, err := LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if pack.ServiceIdentities["elbv2"].ID != "Elastic Load Balancing v2" {
		t.Fatal("missing pinned SDK identity")
	}
	// Source discovery has not found a CREATE handler for aws_lb. Supply a
	// metadata-backed operation fixture to test the runtime join, not invent
	// a production aws_lb rule or pretend it is currently supported.
	pack.Resources = map[string]ResourceRule{"fixture": {Actions: map[string]ActionRule{"create": {Operations: []OperationRule{{Service: "elbv2", Name: "CreateLoadBalancer", Permission: "elasticloadbalancing:CreateLoadBalancer"}}}}}}
	got, ok := NewOperationPermissions(pack).Resolve("Elastic Load Balancing v2", "CreateLoadBalancer")
	if !ok || got != "elasticloadbalancing:CreateLoadBalancer" {
		t.Fatalf("%s %v", got, ok)
	}
}
