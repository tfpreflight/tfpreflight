// Package rules defines tfpreflight's knowledge-pack format and the code that
// reads, writes, signs and verifies packs.
//
// It is not a public API. It lives outside internal/ only so that the build
// that produces tfpreflight's packs can import it. It makes no compatibility
// promise: any exported name may change or disappear in any release,
// including a patch release. Do not import it.
package rules
