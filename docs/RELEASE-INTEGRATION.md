# Release integration records

## v0.4.23 integration qualification

The connector-side foundation does not establish end-to-end Core lifecycle
support. Core enrollment/session authority, shared canonical wire fixtures and
real remote Docker/rootless Podman qualification are tracked in this repository's
#3 and Core #807/#808. Exact source revisions and qualification receipts are retained as CI evidence;
protected credentials are excluded. Cross-build success does not qualify a platform
for runtime or terminal support.

Enrollment destinations must use HTTPS with pinned server identity, without
embedded credentials, query parameters or fragments. Bootstrap credentials are
read exclusively from the protected authorization file.

## Pinned Core wire and bootstrap binding

The canonical schema and synthetic golden records are acquired from immutable
public Core commit specified in the source lock. The source revision and
SHA-256 digests are in `internal/targetaccess/canonical/source-lock.json`; source
CI compares both files byte for byte with that commit. Contract version remains
v1 and is a pre-freeze draft. Production frames reject unknown fields, duplicate
JSON keys, missing correlation/deadlines and malformed typed payloads.

Configure `--tenant-id` with the Core tenant UUID. Node identity is
`spiffe://baseharbor/platform/connectors/<tenant>/<target>/<node>`.
Core identity is `spiffe://baseharbor/platform/core/control-plane`.
The private `--bootstrap-authorization-file` contains the Core-issued JSON
`{"token":"...","nonce":"...","expires_at":"..."}`; it is not a bare token.
The Connector uses that nonce unchanged, rejects expired/unbounded or non-private
files, generates its own private key and sends only its signed CSR. The consumed
authorization file is removed after successful installation by default.
A signing/interruption failure requires a fresh Core authorization.

Requests and streams carry bounded absolute deadlines. Sessions and writes are
bounded, streamed chunks are at most 16 KiB, and terminal input rejects sequence
or correlation mismatch. This source change does not prove production Core
enrollment routing, durable destructive admission, active revocation/rotation
or remote Docker/rootless Podman cleanup. Those integration requirements remain
open before a live remote capability or release approval can be claimed.

Open sessions revalidate the configured peer trust and revocation files every
five seconds, including during idle periods and active streams. Missing or
invalid trust, a removed authority or a revoked peer closes the session and
cancels its operation context. New connections reload current identity material;
interrupted operations and terminal input are never automatically replayed.
TLS session tests verify peer retirement, but production OpenBao rotation,
persisted Core admission and actual runtime lifecycle evidence remain required.

For certificate renewal, obtain a fresh owner-only authorization file from
Core's protected `POST /api/v1/connectors/renewal-authorizations` endpoint and
restart this same node with `--renew-certificate` plus its existing bootstrap
URL/CA and authorization-file settings. Renewal retains the existing locally
held private key and stable tenant/Target/node/runtime identity, validates the
replacement before installing it, and consumes the authorization once. It does
not replay runtime requests or terminal input from old sessions. Coordinate
Core server-certificate and CA overlap changes before switching node trust;
this explicit renewal option is not an automatic rotation controller.

## Durable side-effect admission

On Linux the daemon binds a private `transport/` journal to its immutable
tenant/Target/node/runtime identity. Runtime mutations, exec, artifact staging
and terminal opens persist transport admission before invocation. File locking,
exclusive creation, file synchronization and directory synchronization prevent
a second admitted invocation across workers and restarts. The journal stores
scope/request/content digests and admission time; it stores no payloads,
credentials, desired state or results.

A repeated identifier returns `replay_ambiguous`; changed content returns
`replay_conflict`. Neither executes again. Core must reconcile observed state
and obtain a new authorized request when appropriate. Interrupted or corrupt
records fail closed. The bounded journal never automatically forgets admission.
An unavailable journal suppresses side-effect capabilities. This implementation
uses a protected local Linux filesystem; it does not qualify remote execution,
rotation or active-session revocation by itself.

## v0.4.24 integration candidate and acceptance boundary

The current immutable Core/Console/Demo matrix is recorded in `integration-candidate.json`; the Connector commit is the exact qualified workflow source. Final source revisions, actual Docker/Podman native qualification and their acceptance scope are recorded in [Core PR #837](https://github.com/mcpdev80/baseharbor/pull/837). Earlier source receipts do not qualify a newer matrix.

The v0.4.24 joint runtime candidate is defined by immutable Core, Console and Demo commits in `integration-candidate.json`. The targeted Docker/Podman matrix exercises native managed enrollment, mTLS, rotation, replay/revocation and the real Console OIDC/RBAC/application journeys against that same Core. Runtime results are pending until recorded in Core PR #837.
