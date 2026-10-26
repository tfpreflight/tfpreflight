package awscall

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/rules"
)

// The engine sends nothing for a spec that is not a read, however the spec
// reached it, and sends nothing to a pack host outside AWS.
func TestEngineSendsOnlyReadOnlyLookups(t *testing.T) {
	specs := loadSpecs(t)
	base := specs["DescribeTable"]
	for name, mutate := range map[string]func(*Spec){
		"write operation": func(s *Spec) { s.Operation, s.Target = "DeleteTable", "DynamoDB_20120810.DeleteTable" },
		"target mismatch": func(s *Spec) { s.Target = "DynamoDB_20120810.DeleteTable" },
		"foreign host": func(s *Spec) {
			s.Endpoints.Standard.Partitions = map[string]rules.Host{"aws": {Hostname: "dynamodb.{region}.example.net"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := base
			spec.Endpoints.Standard.Partitions = map[string]rules.Host{}
			for partition, host := range base.Endpoints.Standard.Partitions {
				spec.Endpoints.Standard.Partitions[partition] = host
			}
			mutate(&spec)
			client := &fakeClient{responses: []recorded{{Status: 200}}}
			var slept []time.Duration
			answer := testEngine(client, &slept).Inspect(context.Background(), spec, "us-east-1", map[string]string{spec.Field: "orders"})
			if len(client.requests) != 0 {
				t.Fatalf("sent %d requests", len(client.requests))
			}
			if answer.Result != Unknown || answer.Failure == nil || !strings.Contains(answer.Failure.Cause, "not a read-only lookup") {
				t.Fatalf("answer = %+v", answer)
			}
		})
	}
}

// A pack host is resolved only inside AWS, even for a region the client does
// not check; an endpoint URL the user configured may point anywhere.
func TestTargetKeepsPackHostsInAWS(t *testing.T) {
	spec := loadSpecs(t)["DescribeTable"]
	spec.Endpoints.UncheckedRegion = true
	var slept []time.Duration
	engine := testEngine(&fakeClient{}, &slept)
	if _, err := engine.Target(spec, "us-east-1"); err != nil {
		t.Fatalf("AWS host refused: %v", err)
	}
	if _, err := engine.Target(spec, "evil.example.net/x"); err == nil || !strings.Contains(err.Error(), "not in an AWS partition") {
		t.Fatalf("err = %v, want a refused host", err)
	}
	custom := "http://127.0.0.1:4566"
	engine.BaseEndpoint = &custom
	target, err := engine.Target(spec, "us-east-1")
	if err != nil || target.URL.Host != "127.0.0.1:4566" {
		t.Fatalf("configured endpoint = %v, %v", target.URL, err)
	}
}
