package awscall

import (
	"context"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/rules"
)

// Endpoint settings an SDK client reads from its config sources, through the
// SDK's own interfaces.
type (
	serviceBaseEndpointProvider interface {
		GetServiceBaseEndpoint(ctx context.Context, sdkID string) (string, bool, error)
	}
	ignoreConfiguredEndpointsProvider interface {
		GetIgnoreConfiguredEndpoints(ctx context.Context) (bool, bool, error)
	}
	useFIPSEndpointProvider interface {
		GetUseFIPSEndpoint(ctx context.Context) (aws.FIPSEndpointState, bool, error)
	}
	useDualStackEndpointProvider interface {
		GetUseDualStackEndpoint(ctx context.Context) (aws.DualStackEndpointState, bool, error)
	}
)

// endpointSettings are the FIPS and dual-stack settings, read once from the
// config sources as every SDK client reads them.
func endpointSettings(sources []any) (fips, dualStack bool) {
	for _, source := range sources {
		if p, ok := source.(useFIPSEndpointProvider); ok {
			value, found, err := p.GetUseFIPSEndpoint(context.Background())
			if err != nil {
				break
			}
			if found {
				fips = value == aws.FIPSEndpointStateEnabled
				break
			}
		}
	}
	for _, source := range sources {
		if p, ok := source.(useDualStackEndpointProvider); ok {
			value, found, err := p.GetUseDualStackEndpoint(context.Background())
			if err != nil {
				break
			}
			if found {
				dualStack = value == aws.DualStackEndpointStateEnabled
				break
			}
		}
	}
	return fips, dualStack
}

// baseEndpoint is a configured endpoint URL for the service, chosen as the SDK
// chooses it: the global one, unless a service-specific one is set and
// configured endpoints are not ignored.
func (e *Engine) baseEndpoint(sdkID string) string {
	base := ""
	if e.BaseEndpoint != nil {
		base = *e.BaseEndpoint
	}
	_, global := os.LookupEnv("AWS_ENDPOINT_URL")
	_, service := os.LookupEnv("AWS_ENDPOINT_URL_" + strings.ReplaceAll(strings.ToUpper(sdkID), " ", "_"))
	if global && !service {
		return base
	}
	if e.ignoresConfiguredEndpoints() {
		return base
	}
	if value, found := e.serviceEndpoint(sdkID); found {
		return value
	}
	return base
}

// ignoresConfiguredEndpoints reads the first config source that says whether
// configured endpoints are ignored; a failing source ends the search.
func (e *Engine) ignoresConfiguredEndpoints() bool {
	for _, source := range e.ConfigSources {
		p, ok := source.(ignoreConfiguredEndpointsProvider)
		if !ok {
			continue
		}
		value, found, err := p.GetIgnoreConfiguredEndpoints(context.Background())
		if err != nil {
			return false
		}
		if found {
			return value
		}
	}
	return false
}

// serviceEndpoint reads the first configured endpoint for the service; a failing
// source ends the search.
func (e *Engine) serviceEndpoint(sdkID string) (string, bool) {
	for _, source := range e.ConfigSources {
		p, ok := source.(serviceBaseEndpointProvider)
		if !ok {
			continue
		}
		value, found, err := p.GetServiceBaseEndpoint(context.Background(), sdkID)
		if err != nil {
			return "", false
		}
		if found {
			return value, true
		}
	}
	return "", false
}

// Target resolves where a lookup in region goes, as an SDK client configured the
// same way would send it.
func (e *Engine) Target(spec Spec, region string) (rules.Target, error) {
	return rules.ResolveTarget(spec, e.Partitions, region, rules.EndpointSettings{
		FIPS: e.fips, DualStack: e.dualStack, BaseEndpoint: e.baseEndpoint(spec.SDKID),
	})
}

type enableEndpointDiscoveryProvider interface {
	GetEnableEndpointDiscovery(ctx context.Context) (aws.EndpointDiscoveryEnableState, bool, error)
}

func discoveryEnabled(sources []any) bool {
	for _, source := range sources {
		if p, ok := source.(enableEndpointDiscoveryProvider); ok {
			value, found, err := p.GetEnableEndpointDiscovery(context.Background())
			if err != nil {
				return false
			}
			if found {
				return value == aws.EndpointDiscoveryEnabled
			}
		}
	}
	return false
}

// Discovers reports whether an SDK client configured like this engine would
// discover the spec's endpoint. The engine does not, so such a lookup goes to
// the SDK client.
func (e *Engine) Discovers(spec Spec) bool {
	return spec.EndpointDiscovery != "" && e.discovery
}
