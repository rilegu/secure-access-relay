// Package operator implements the operator-side forwarder.
//
// It listens on a local address, and carries each accepted connection through
// the relay to an approved service on an endpoint. The listener is bound to
// loopback so that opening a forward exposes it to the operator's own machine
// and not to their network.
//
// The operator names what they want to reach; they never supply a target
// address. Resolving a name to an address is the endpoint agent's job, against
// its own allowlist. That asymmetry is the difference between a resource proxy
// and a tunnel, so this package deliberately has no way to express a destination.
package operator
