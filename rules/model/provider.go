package model

import "strings"

// Provider is a normalized provider identifier.
type Provider string

// Providers a plan's resources are normalized to.
const (
	ProviderAWS        Provider = "aws"
	ProviderAzure      Provider = "azure"
	ProviderGCP        Provider = "gcp"
	ProviderKubernetes Provider = "kubernetes"
	ProviderUnknown    Provider = "unknown"
)

// NormalizeProvider maps Terraform provider source addresses to provider families.
func NormalizeProvider(name string) Provider {
	parts := strings.Split(strings.ToLower(name), "/")
	provider := parts[len(parts)-1]
	switch provider {
	case "aws":
		return ProviderAWS
	case "azurerm":
		return ProviderAzure
	case "google", "google-beta":
		return ProviderGCP
	case "kubernetes":
		return ProviderKubernetes
	default:
		return ProviderUnknown
	}
}

// ProvidersForChanges returns unique normalized providers in first-seen order.
func ProvidersForChanges(changes []PlannedChange) []Provider {
	providers := make([]Provider, 0)
	seen := make(map[Provider]bool)
	for _, change := range changes {
		provider := NormalizeProvider(change.ProviderName)
		if !seen[provider] {
			providers = append(providers, provider)
			seen[provider] = true
		}
	}
	return providers
}
