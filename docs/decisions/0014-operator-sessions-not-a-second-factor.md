# ADR-0014: Operator sessions are a revocation handle, not a second factor

**Status:** accepted

## Context

An operator authenticates with a certificate obtained at enrollment
([ADR-0010](0010-certificate-is-the-identity.md)). That certificate lasts thirty days,
lives sealed on the operator's machine, and is the only thing the control plane checks
before issuing a grant.

Two problems follow from it being the *only* thing.

**Revocation is too coarse.** The only lever an administrator has is revoking the
identity, which means re-enrolling the operator afterwards. There is nothing between "you
are fine" and "you must be re-issued a certificate", so the response to *"Maria's laptop
was left in a taxi, probably fine, but"* is either nothing or a disruption.

**Attribution is reconstructed rather than recorded.** Answering *"what did Maria do
during Tuesday's incident"* means selecting audit rows by actor and guessing at time
boundaries. There is no object representing a period of work.

The obvious framing — "add a login" — is a trap. It suggests a password or a second
factor, and this design has neither.

## Decision

`sarctl login` opens an **operator session**: a short-lived, revocable, server-side
object identified by `ses_...`, addressed by a bearer token the client stores sealed. A
grant request must carry both the certificate and a live session token, and the grant
records the session it was issued under.

**The session is explicitly not a second authentication factor.** Anyone holding the
certificate can open one, with no additional secret. This is stated in the package doc,
the README, the threat model, and the CLI help, because the failure mode of an
unqualified "login" is that somebody believes the system has two factors when it has one.

What it is:

1. **A revocation lever shorter than a certificate.** Eight hours by default, capped at
   twenty-four. Ending a session revokes the grants issued under it and drops the streams
   those grants opened.
2. **A unit of attribution.** Every grant names its session, so an operator's activity
   during one period is a single query.
3. **The seam an identity provider plugs into.** When login means OIDC, the thing it
   produces is this session. Nothing downstream changes.

Both are required together: a token presented with a different certificate is refused,
and a certificate presented without a token is refused. Neither is sufficient alone,
which is what stops a leaked token being a credential in its own right.

## Rejected: no session, revoke the certificate instead

The status quo. It leaves a thirty-day credential as the only unit of revocation, and it
leaves an administrator with no proportionate response to a suspicion.

It also cannot express "end this operator's current work but let them log in again
tomorrow", which is the ordinary case.

## Rejected: a password or TOTP as a second factor

This would be a real second factor and was considered.

It was rejected because it would be **custom authentication**, which is a stated non-goal
and a category this project has no business inventing. Password storage, reset flows,
lockout policy, and enrollment of a second factor are each a place to be subtly wrong,
and the correct answer to all of them is an identity provider — which is deferred, not
replaced by writing a worse one.

Adding a weak second factor would also be actively harmful: it would let the README claim
multi-factor authentication for something an attacker with the operator's laptop defeats
by reading the same disk the certificate is on.

## Rejected: session tokens instead of certificates on the data plane

Simpler on paper — one credential rather than two. Rejected because it would replace a
key-backed, per-machine credential with a bearer string, on the connection that carries
customer traffic. The certificate is the stronger credential; the session is scoped
metadata layered on top of it.

## Rejected: making a session optional

Considered, so that `sarctl connect` would work with no prior step. Rejected in that form
because a control plane where sessions are advisory has grants that cannot be grouped or
revoked as a set, which removes both reasons the session exists.

Resolved instead by making `sarctl connect` **open a session automatically** if there is
no usable one. A session is not a factor, so requiring an explicit login before every
forward would add a step without adding a check — and what it would really add is an
operator who scripts around it. Explicit `sarctl login` remains, for holding one session
across many forwards.

## Consequences

- A grant request needs two credentials. A deployment that has not upgraded `sarctl` will
  see grant requests refused with a message naming the missing session.
- Session tokens are bearer values and are stored sealed, through the same keystore that
  protects the private key — DPAPI on Windows.
- A session token is never printed by the CLI, never logged, and never written to the
  audit trail. The session *identifier* is all three, because it is what an administrator
  needs in order to end a session and is useless as a credential.
- Ending a session is now three writes — the session row, its grants, the live streams —
  and they can fail independently. They are performed in that order and reported
  separately, so a partial failure names which part did not happen.
- Sessions expire on their own. There is no sweep; an expired session is refused on use
  and remains in the table as audit history.
