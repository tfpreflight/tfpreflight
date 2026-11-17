package dependencies

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/packs"
)

// Before beta.8 the runtime kept a table of types whose id AWS picks, because the
// pack said "unknown". The pack builder now reads those ids itself. These are
// the types the table held; the shipped pack must call each one's id
// server-generated at every provider version it has a rule for.
var formerlyAssignedIDs = []string{
	"aws_security_group", "aws_ec2_transit_gateway", "aws_directory_service_directory",
	"aws_ebs_snapshot", "aws_network_interface", "aws_instance", "aws_efs_file_system",
	"aws_prometheus_workspace", "aws_transfer_server", "aws_vpc_endpoint_service",
	"aws_sagemaker_domain", "aws_ec2_traffic_mirror_filter", "aws_ssm_maintenance_window",
	"aws_servicecatalog_tag_option", "aws_vpc_ipam_resource_discovery",
}

func TestShippedPackKnowsWhichIDsAWSAssigns(t *testing.T) {
	data, err := packs.AWS.ReadFile("aws/dependency/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Fields []struct {
			Name    string `json:"name"`
			Entries []struct {
				Versions [][]string      `json:"versions"`
				Value    json.RawMessage `json:"value"`
			} `json:"entries"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, typ := range formerlyAssignedIDs {
		want[typ] = true
	}
	checked := 0
	var wrong []string
	for _, field := range pack.Fields {
		if field.Name != "existence_rules" {
			continue
		}
		for _, entry := range field.Entries {
			var rule ExistenceRule
			if err := json.Unmarshal(entry.Value, &rule); err != nil {
				t.Fatal(err)
			}
			if !want[rule.TargetResource] || rule.TargetAttribute != "id" {
				continue
			}
			checked++
			if rule.TargetIdentity != IdentityServerGenerated {
				wrong = append(wrong, rule.Resource+" -> "+rule.TargetResource+" "+rule.TargetIdentity+" "+versionText(entry.Versions))
			}
		}
	}
	if checked == 0 {
		t.Fatal("the pack has no rule that targets one of these types")
	}
	if len(wrong) > 0 {
		t.Errorf("the pack does not call these ids server-generated, so a plan that creates the target would make the check undecidable:\n  %s", strings.Join(wrong, "\n  "))
	}
}

func versionText(ranges [][]string) string {
	var parts []string
	for _, r := range ranges {
		parts = append(parts, strings.Join(r, "-"))
	}
	return strings.Join(parts, ",")
}
