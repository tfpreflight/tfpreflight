package plan

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

type planJSON struct {
	ResourceChanges []resourceChangeJSON `json:"resource_changes"`
	Configuration   struct {
		RootModule configModuleJSON `json:"root_module"`
	} `json:"configuration"`
}

type resourceChangeJSON struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	ResourceType  string `json:"type"`
	Name          string `json:"name"`
	ProviderName  string `json:"provider_name"`
	Change        struct {
		Actions      []string `json:"actions"`
		Before       any      `json:"before"`
		After        any      `json:"after"`
		AfterUnknown any      `json:"after_unknown"`
	} `json:"change"`
}

type configModuleJSON struct {
	Resources []struct {
		Address           string `json:"address"`
		ProviderConfigKey string `json:"provider_config_key"`
	} `json:"resources"`
	ModuleCalls map[string]struct {
		Module configModuleJSON `json:"module"`
	} `json:"module_calls"`
}

// ParsePlan extracts the resource changes from `terraform show -json` output,
// leaving out data source reads.
func ParsePlan(data []byte) ([]model.PlannedChange, error) {
	var plan planJSON
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse plan JSON: %w", err)
	}
	providerKeys := map[string]string{}
	collectProviderKeys(plan.Configuration.RootModule, "", providerKeys)

	changes := make([]model.PlannedChange, 0, len(plan.ResourceChanges))
	for _, resource := range plan.ResourceChanges {
		action, include := classifyAction(resource.Change.Actions)
		if !include {
			continue
		}
		changes = append(changes, model.PlannedChange{
			Address:           resource.Address,
			ResourceType:      resource.ResourceType,
			ProviderName:      resource.ProviderName,
			ProviderConfigKey: providerKeys[configAddress(resource)],
			Action:            action,
			Before:            resource.Change.Before,
			After:             resource.Change.After,
			AfterUnknown:      resource.Change.AfterUnknown,
		})
	}
	return changes, nil
}

// collectProviderKeys maps each configured resource block, by its address
// without instance keys, to the provider configuration Terraform resolved
// for it.
func collectProviderKeys(module configModuleJSON, path string, keys map[string]string) {
	for _, resource := range module.Resources {
		keys[qualified(path, resource.Address)] = resource.ProviderConfigKey
	}
	for name, call := range module.ModuleCalls {
		collectProviderKeys(call.Module, qualified(path, "module."+name), keys)
	}
}

var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// configAddress is the configuration block a resource change belongs to:
// module.a[0].aws_s3_bucket.b["x"] belongs to module.a.aws_s3_bucket.b.
func configAddress(resource resourceChangeJSON) string {
	return qualified(instanceKey.ReplaceAllString(resource.ModuleAddress, ""), resource.ResourceType+"."+resource.Name)
}

func qualified(path, address string) string {
	if path == "" {
		return address
	}
	return path + "." + address
}

func classifyAction(actions []string) (model.Action, bool) {
	var create, update, deleteAction, noOp bool
	for _, action := range actions {
		switch action {
		case "create":
			create = true
		case "update":
			update = true
		case "delete":
			deleteAction = true
		case "no-op":
			noOp = true
		}
	}
	if create && deleteAction {
		return model.ActionReplace, true
	}
	if create {
		return model.ActionCreate, true
	}
	if update {
		return model.ActionUpdate, true
	}
	if deleteAction {
		return model.ActionDelete, true
	}
	if noOp {
		return model.ActionNoOp, true
	}
	return "", false
}
