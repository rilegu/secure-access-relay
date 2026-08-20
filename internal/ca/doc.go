// Package ca implements the development certificate authority that issues
// device and operator certificates.
//
// It exists so that every connection can be attributed to an enrolled identity
// rather than to whatever a peer claims about itself. A certificate signed by
// this authority is the only thing that makes an identity mean anything.
//
// # Development only
//
// This authority is generated locally, stores its key on the same host that
// signs with it, and has no revocation infrastructure beyond short lifetimes and
// an explicit revocation list. A real deployment would use an offline root, an
// HSM, or an existing enterprise PKI. Nothing here should be read as a
// recommendation for how to run a production CA.
//
// # What this package must never do
//
//   - It must never sign a certificate whose identity was not established by the
//     caller. Signing is mechanical; deciding who deserves a certificate is an
//     enrollment decision and lives elsewhere.
//   - It must never write a private key anywhere except through the caller.
package ca
