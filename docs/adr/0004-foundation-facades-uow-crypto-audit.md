# ADR 0004: Foundation facades, atomic journal and crypto provider

- Status: accepted
- Date: 2026-07-29
- Release: 0.4.0

## Context

The historical `AuthService` exposed identity, authentication, MFA, recovery,
session and outbox operations through one public surface. Storage methods were
documented as atomic, but the composition root did not require adapters to
declare state/outbox/audit rollback guarantees. Sealed MFA material persisted a
key ID and nonce but no explicit format or algorithm.

## Decision

- `SdkAuth` exposes capability-oriented facades for identity, authentication,
  authenticators, sessions, recovery, audit, IAM and authorization.
- `AuthService` remains an internal compatibility implementation during 0.x;
  bindings must migrate to the capability facades before 1.0.
- Every adapter used by `SdkAuth` implements `UnitOfWorkStore` and declares the
  required atomic journal guarantees. A journaled mutation commits state,
  append-only audit and an optional outbox event in one transaction or critical
  section.
- Audit records are separate from delivery events and have no delete or
  acknowledgement API. Reading them requires fresh IAM step-up and
  `iam.audit:read`; outbox delivery uses a separate trusted-host facade.
- Audit records use `AuditId`; delivery events use `EventId`. Audit-only login,
  email-verification and session-revocation records do not inflate the outbox.
- Cryptographic capabilities may be supplied as one `CryptoProvider`. Mixing a
  provider with legacy individual capabilities is rejected.
- Sealed secrets persist an explicit format version and AEAD algorithm. Unknown
  formats or algorithms fail closed.
- Session assurance is derived conservatively from evidence already persisted;
  trusted-device metadata never upgrades assurance by itself.
- SQLite schema 4 introduces compatibility metadata. A reader/writer accepts a
  future additive schema only when that schema explicitly declares it safe.

## Consequences

- Custom stores must add `AuditStore` and `UnitOfWorkStore` implementations.
- SQLite migration 4 is mandatory before opening the store.
- The 0.4 public surface changes during the permitted pre-1.0 compatibility
  window.
- The internal `AuthService` remains large. Physical use-case decomposition is
  deferred until the facade contract has been exercised by adapters/bindings.
- Token digests remain BLAKE3 v1 in this release. Moving to keyed HMAC requires
  a dual-verifier migration so existing tokens are not invalidated silently.

## Rejected alternatives

- Framework-specific services: violates the hexagonal boundary.
- Generic transaction closures in public async traits: difficult to keep
  dyn-compatible and leaks adapter lifetimes.
- Reusing outbox as the audit log: delivery acknowledgement and retention have
  different security semantics.
- Silent token-digest algorithm replacement: would revoke all outstanding
  credentials and prevent controlled key rotation.
