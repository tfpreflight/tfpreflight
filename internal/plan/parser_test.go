package plan

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestParsePlanClassifiesActions(t *testing.T) {
	data := []byte(`{"resource_changes":[
		{"address":"aws_instance.new","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"name":"new"},"after_unknown":{"id":true}}},
		{"address":"aws_instance.changed","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["update"],"before":{"name":"old"},"after":{"name":"new"}}},
		{"address":"aws_instance.gone","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["delete"],"before":{"name":"old"},"after":null}},
		{"address":"aws_instance.replaced","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["delete","create"],"before":{"name":"old"},"after":{"name":"new"}}},
		{"address":"aws_instance.same","type":"aws_instance","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["no-op"],"before":{},"after":{}}},
		{"address":"data.aws_region.current","type":"aws_region","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["read"],"before":null,"after":{}}}
	]}`)

	changes, err := ParsePlan(data)
	if err != nil {
		t.Fatalf("ParsePlan: %v", err)
	}
	if len(changes) != 5 {
		t.Fatalf("len(changes) = %d, want 5", len(changes))
	}
	want := []model.Action{model.ActionCreate, model.ActionUpdate, model.ActionDelete, model.ActionReplace, model.ActionNoOp}
	for index, action := range want {
		if changes[index].Action != action {
			t.Errorf("changes[%d].Action = %q, want %q", index, changes[index].Action, action)
		}
	}
	if changes[0].Address != "aws_instance.new" || changes[0].ResourceType != "aws_instance" {
		t.Errorf("unexpected resource details: %#v", changes[0])
	}
	if unknown, ok := changes[0].AfterUnknown.(map[string]any); !ok || unknown["id"] != true {
		t.Errorf("after_unknown was not parsed: %#v", changes[0].AfterUnknown)
	}
}

func TestParsePlanRejectsInvalidJSON(t *testing.T) {
	if _, err := ParsePlan([]byte(`not json`)); err == nil {
		t.Fatal("ParsePlan() returned nil error for invalid JSON")
	}
}
