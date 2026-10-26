// Package packs holds every knowledge pack built into the tfpreflight binary,
// and is the only copy of each. One copy means the binary cannot ship packs that
// differ from the ones reviewed. Nothing here interprets a pack; internal/packs
// does.
package packs

import "embed"

// AWS holds the AWS provider's knowledge packs. Each pack kind is one range pack
// covering every built provider version:
//
//	aws/generated/     permissions, quota rules and the verified overlay
//	aws/conflict/      curated and generated identity-conflict rules
//	aws/dependency/    dependency rules and their enforcement evidence
//	aws/knowledge/     the hand-written pack
//	aws/lookup/        AWS lookup specs for the generic engine
//	aws/manifest.json  every file above, its SHA-256, and the covered versions
//
// The runtime reads them only through internal/packs, which checks the manifest
// first.
//
//go:embed aws
var AWS embed.FS
