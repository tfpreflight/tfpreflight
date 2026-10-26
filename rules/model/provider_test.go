package model

import "testing"

func TestNormalizeProvider(t *testing.T) {
	tests := map[string]Provider{
		"registry.terraform.io/hashicorp/aws":         ProviderAWS,
		"registry.terraform.io/hashicorp/azurerm":     ProviderAzure,
		"registry.terraform.io/hashicorp/google":      ProviderGCP,
		"registry.terraform.io/hashicorp/kubernetes":  ProviderKubernetes,
		"registry.terraform.io/cloudflare/cloudflare": ProviderUnknown,
	}
	for name, want := range tests {
		if got := NormalizeProvider(name); got != want {
			t.Errorf("NormalizeProvider(%q) = %q, want %q", name, got, want)
		}
	}
}
