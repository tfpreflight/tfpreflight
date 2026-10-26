// Package adapters answers dependency existence lookups: through the generic AWS
// engine for every lookup with a spec, and through generated SDK clients for the
// few without one.
package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/tfpreflight/tfpreflight/internal/awscall"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// Rules reads the dependency rules for a covered provider version. The generated
// SDK adapters serve the lookups of every version, as the engine's specs do.
func Rules(version string) ([]dependencies.ExistenceRule, error) {
	data, err := packs.ReadFile("aws/dependency/rules-" + version + ".json")
	if err != nil {
		return nil, fmt.Errorf("dependency knowledge unavailable for AWS provider %s: %w", version, err)
	}
	var pack struct {
		Version string                       `json:"provider_version"`
		Rules   []dependencies.ExistenceRule `json:"existence_rules"`
	}
	if err = json.Unmarshal(data, &pack); err != nil {
		return nil, err
	}
	if pack.Version != version {
		return nil, fmt.Errorf("dependency pack version mismatch")
	}
	return pack.Rules, nil
}

type (
	lookupFunc func(context.Context, dependencies.Lookup, dependencies.Scope, string) (dependencies.Existence, string)
	answer     struct {
		state  dependencies.Existence
		reason string
	}
)

// lookupTimeout caps one inspection, so a service that never answers costs its
// own dependency a verdict, not the whole check.
var lookupTimeout = 15 * time.Second

// maxConcurrentLookups is deliberately modest: a preflight check is a guest in
// someone's account, and hundreds of dependencies should not arrive as a burst.
const maxConcurrentLookups = 8

type call struct {
	done   chan struct{}
	answer answer
}

// clientCache builds one SDK client per region, once. Generated lookups run
// concurrently, so clients are built under a lock.
type clientCache[T any] struct {
	mu       sync.Mutex
	build    func(string) T
	byRegion map[string]T
}

func newClientCache[T any](build func(string) T) *clientCache[T] {
	return &clientCache[T]{build: build, byRegion: map[string]T{}}
}

func (c *clientCache[T]) get(region string) T {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.byRegion[region]; ok {
		return client
	}
	client := c.build(region)
	c.byRegion[region] = client
	return client
}

// Registry answers the lookups of one check with one AWS configuration, asking
// each question at most once. Scope and alias checks happen before it is called.
type Registry struct {
	mu          sync.Mutex
	lookups     map[string]lookupFunc
	approved    map[string]bool
	cache       map[string]answer
	inflight    map[string]*call
	unavailable string
	// answered counts the lookups sent to AWS that it answered; failures are
	// why the others got no answer.
	answered int
	failures []string
}

// Lookups reports how many lookups sent to AWS got an answer, and why the rest
// did not. A lookup refused before sending is neither.
func (r *Registry) Lookups() (answered int, failures []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.answered, append([]string(nil), r.failures...)
}

// New builds the registry for one provider version's dependency rules. When the
// rules or lookup specs cannot be loaded, or the linked SDK modules differ from
// the pinned ones, every lookup answers unknown with the reason.
func New(version string, config aws.Config) *Registry {
	r := &Registry{cache: map[string]answer{}, approved: map[string]bool{}, inflight: map[string]*call{}}
	rules, err := Rules(version)
	if err != nil {
		r.unavailable = err.Error()
		return r
	}
	if module := linkedSDKMismatch(); module != "" {
		r.unavailable = "linked SDK module differs from provider manifest: " + module
		return r
	}
	for _, rule := range rules {
		r.approved[semantics(rule.Lookup)] = true
	}
	// Lookups with a spec go through the generic engine; the rest stay on their
	// SDK clients.
	sdk := generatedRegistry(config)
	engine, err := engineLookups(version, config, rules)
	if err != nil {
		r.unavailable = err.Error()
		return r
	}
	r.lookups = map[string]lookupFunc{}
	for key, fn := range sdk {
		r.lookups[key] = fn
	}
	for key, fn := range engine {
		r.lookups[key] = fn
	}
	return r
}

// linkedSDKMismatch names an AWS SDK module linked at a version other than the
// pinned one, or "". Test binaries do not always carry module data; release
// binaries must match the pins.
func linkedSDKMismatch() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || len(info.Deps) == 0 {
		return ""
	}
	actual := map[string]string{}
	for _, m := range info.Deps {
		if m.Replace == nil {
			actual[m.Path] = m.Version
		}
	}
	for module, version := range sdkVersions {
		if actual[module] != version {
			return module
		}
	}
	return ""
}

// Exists answers one lookup, asking AWS at most once per question per check. The
// question is the scope, the lookup and the identifier: the same id elsewhere is
// a different question. A caller that arrives while the same lookup is in flight
// waits for it.
func (r *Registry) Exists(ctx context.Context, l dependencies.Lookup, scope dependencies.Scope, id string) (dependencies.Existence, string) {
	if err := ctx.Err(); err != nil {
		return dependencies.Unknown, err.Error()
	}
	if r.unavailable != "" {
		return dependencies.Unknown, r.unavailable
	}
	if id == "" || !r.approved[semantics(l)] {
		return dependencies.Unknown, "unregistered identifier or lookup semantics"
	}
	fn := r.lookups[lookupKey(l)]
	if fn == nil {
		return dependencies.Unknown, "typed lookup adapter unavailable: " + lookupKey(l)
	}
	key := scope.Key() + "\x00" + semantics(l) + "\x00" + id

	r.mu.Lock()
	if cached, ok := r.cache[key]; ok {
		r.mu.Unlock()
		return cached.state, cached.reason
	}
	if pending, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		select {
		case <-pending.done:
			return pending.answer.state, pending.answer.reason
		case <-ctx.Done():
			return dependencies.Unknown, ctx.Err().Error()
		}
	}
	pending := &call{done: make(chan struct{})}
	r.inflight[key] = pending
	r.mu.Unlock()

	inspection, done := context.WithTimeout(ctx, lookupTimeout)
	state, reason := fn(inspection, l, scope, id)
	done()
	pending.answer = answer{state, reason}
	r.mu.Lock()
	delete(r.inflight, key)
	if state == dependencies.Unknown {
		r.failures = append(r.failures, reason)
	} else {
		r.answered++
	}
	// An answer produced while the check was being cancelled says nothing about
	// the identifier, so it is not remembered.
	if ctx.Err() == nil {
		r.cache[key] = pending.answer
	}
	r.mu.Unlock()
	close(pending.done)
	return state, reason
}

// Prefetch resolves lookups ahead of evaluation, a bounded number at a time, and
// returns when all have answers or the check is cancelled. Evaluation still asks
// for each identifier and reads the answers left behind.
func (r *Registry) Prefetch(ctx context.Context, requests []dependencies.LookupRequest) {
	if r.unavailable != "" || len(requests) == 0 || ctx.Err() != nil {
		return
	}
	workers := min(maxConcurrentLookups, len(requests))
	work := make(chan dependencies.LookupRequest)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for request := range work {
				if ctx.Err() != nil {
					return
				}
				r.Exists(ctx, request.Lookup, request.Scope, request.Identifier)
			}
		}()
	}
	for _, request := range requests {
		select {
		case work <- request:
		case <-ctx.Done():
			close(work)
			group.Wait()
			return
		}
	}
	close(work)
	group.Wait()
}

// errorTypeName is the SDK type the response deserialised into.
func errorTypeName(err error) string {
	kind := reflect.TypeOf(err)
	for kind != nil && kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == nil {
		return ""
	}
	return kind.Name()
}

// lookupKey is the key the generated adapters and the lookup specs are both
// indexed by.
func lookupKey(l dependencies.Lookup) string { return l.Service + "/" + l.Operation + "/" + l.Field }

func semantics(l dependencies.Lookup) string { data, _ := json.Marshal(l); return string(data) }
func lookupError(err error, l dependencies.Lookup) (dependencies.Existence, string) {
	var api smithy.APIError
	if errors.As(err, &api) {
		code := api.ErrorCode()
		for _, allowed := range l.NotFoundCodes {
			if code == allowed {
				return dependencies.NotFound, "authoritative not-found: " + code
			}
		}
		// The AWS model's own not-found type counts too, and its Go type may
		// differ from the wire code: S3 answers a missing bucket with the
		// modelled NotFound type, not NoSuchBucket.
		if l.NotFoundType != "" && (code == l.NotFoundType || errorTypeName(api) == l.NotFoundType) {
			return dependencies.NotFound, "authoritative not-found: modelled " + l.NotFoundType
		}
		return dependencies.Unknown, "AWS inspection error: " + code
	}
	// Raw transport errors may contain request data, so they are not shown.
	if errors.Is(err, context.Canceled) {
		return dependencies.Unknown, "inspection canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return dependencies.Unknown, "inspection timed out"
	}
	return dependencies.Unknown, awscall.TransportFailure
}
