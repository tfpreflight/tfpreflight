package packs

// signingKey is the Ed25519 public key that signs published pack bundles and
// their index. The private key is a CI secret (TFPREFLIGHT_PACK_SIGNING_KEY)
// and never in this repository.
var signingKey = "4hHoNdXGEvjP/QqkgZM0g6t7f+eXmba1WOeYhqJUG/U="
