# SDK-Auth

SDK-Auth models authentication subjects and their authenticators inside an
isolated realm. A person may prove control through several methods without
becoming several users.

## Language

**Realm**:
An isolation boundary in which user identities, credentials, sessions and
authorization policy are unique.
_Avoid_: Tenant, namespace

**User**:
The stable authentication subject inside one realm. A user may own multiple
credentials and federated identities.
_Avoid_: Person, profile, login

**Local credential**:
A password verifier owned by a user and managed directly by the realm.
_Avoid_: Local user, password user

**Federated identity**:
A durable subject asserted by one external issuer and linked to exactly one
user in a realm.
_Avoid_: Social user, OAuth user, provider email

**Identity link**:
The explicit association between a federated identity and a user.
_Avoid_: Merge, email match

**Link challenge**:
A short-lived state requiring proof of control of an existing user before a new
federated identity may be linked.
_Avoid_: Automatic merge

**Provider**:
A configured external identity authority that can produce verified federated
claims.
_Avoid_: Social network, OAuth login

**Verified email claim**:
An email attribute whose ownership the provider asserts. It can help locate a
possible existing user but is never the durable federated identity key.
_Avoid_: External user ID, provider key
