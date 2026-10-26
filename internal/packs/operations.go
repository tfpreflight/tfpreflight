package packs

import (
	"sort"
	"strings"
)

// OperationPermissions maps an AWS SDK API operation to its IAM permission,
// using mappings derived from AWS's own authorization metadata, so nothing is
// invented by string manipulation at lookup time.
type OperationPermissions struct {
	byOperation map[string][]string
	sdkServices map[string]map[string]bool
}

// LoadOperationPermissions indexes the runtime knowledge pack by API operation.
func LoadOperationPermissions(providerVersion string) (OperationPermissions, error) {
	pack, _, err := LoadRuntimePack(providerVersion)
	if err != nil {
		return OperationPermissions{}, err
	}
	return NewOperationPermissions(pack), nil
}

// NewOperationPermissions builds the index from a loaded pack.
func NewOperationPermissions(pack KnowledgePack) OperationPermissions {
	index := OperationPermissions{byOperation: map[string][]string{}, sdkServices: map[string]map[string]bool{}}
	seen := map[string]bool{}
	for _, resource := range pack.Resources {
		for _, action := range resource.Actions {
			for _, operation := range action.Operations {
				index.add(pack, operation, seen)
			}
		}
	}
	for operation := range index.byOperation {
		sort.Strings(index.byOperation[operation])
	}
	return index
}

// add indexes one operation's permission and its SDK service ID. seen lists each
// operation and permission pair once.
func (o OperationPermissions) add(pack KnowledgePack, operation OperationRule, seen map[string]bool) {
	if operation.Name == "" || operation.Permission == "" {
		return
	}
	key := operation.Name + "\x00" + operation.Permission
	service := operation.Service
	if service == "" {
		service, _, _ = strings.Cut(operation.Permission, ":")
	}
	if identity, ok := pack.ServiceIdentities[service]; ok && identity.ID != "" {
		if o.sdkServices[key] == nil {
			o.sdkServices[key] = map[string]bool{}
		}
		o.sdkServices[key][identity.ID] = true
	}
	if seen[key] {
		return
	}
	seen[key] = true
	o.byOperation[operation.Name] = append(o.byOperation[operation.Name], operation.Permission)
}

// Len reports how many distinct API operations are indexed.
func (o OperationPermissions) Len() int { return len(o.byOperation) }

// Resolve maps an AWS SDK service id and operation to an IAM permission. Exactly
// one candidate permission must belong to the named service; otherwise the
// operation stays unresolved rather than guessed.
func (o OperationPermissions) Resolve(serviceID, operation string) (string, bool) {
	candidates := o.byOperation[operation]
	if len(candidates) == 0 || strings.TrimSpace(serviceID) == "" {
		return "", false
	}
	var matched []string
	for _, permission := range candidates {
		if o.sdkServices[operation+"\x00"+permission][serviceID] {
			matched = append(matched, permission)
		}
	}
	if len(matched) != 1 {
		return "", false
	}
	return matched[0], true
}
