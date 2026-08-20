// Package keystore stores a private key on disk with the best protection the
// host offers.
//
// On Windows the key is sealed with DPAPI under the account that runs the
// service, so a copy of the state directory taken to another machine — or read
// by another user on the same machine — is undecryptable. That is the mitigation
// for threat T9.
//
// On other platforms the key is written with owner-only permissions and no
// encryption. That is weaker and is reported as such: an agent says at startup
// which protection it actually got, so nobody has to infer it.
//
// # Deliberately no third-party dependency
//
// DPAPI is reached through the standard library's syscall package rather than an
// external Windows binding. The project has no external dependencies, and this
// is also a rehearsal of the dynamic-loading technique the native diagnostics
// library will use later: resolve the DLL and the entry point at runtime, marshal
// arguments explicitly, own every buffer.
package keystore
