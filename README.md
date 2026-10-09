# BaseHarbor Node Connector

Optional Target Access Provider implementation for remote non-Kubernetes targets.

The Node Connector is **not** a BaseHarbor control plane, not a Runtime Provider and not an autonomous agent.

## Boundary

```text
BaseHarbor Core
  |
  v
Runtime semantics
  |
  v
Target Access Provider
  |
  v
BaseHarbor Node Connector
  |
  v
local/native runtime API
```

The authoritative contract is tracked in `mcpdev80/baseharbor#769`.

## Responsibilities

The connector may provide bounded transport capabilities such as:

- authenticated connection establishment
- runtime capability reporting
- logs / stream transport
- runtime metrics transport
- container exec / terminal transport where authorized
- runtime health/connectivity
- peer identity and trust metadata

## Non-responsibilities

The connector must not own or decide:

- portable Application Intent
- Application/Deployment state
- Provider placement
- Runtime realization semantics
- environment policy
- authorization policy
- HA/availability decisions
- BaseHarbor reconciliation
- a second secret store
- unrestricted generic host shell access

## Security baseline

For BaseHarbor-managed remote connector access:

- mutually authenticated TLS
- no plaintext fallback
- verified peer identity
- certificate rotation / renewal
- revocation and expiry fail closed
- capability negotiation only after authentication
- security-sensitive sessions are auditable
- no unauthenticated management port

The connector uses outbound-initiated persistent mTLS sessions to BaseHarbor Core.
It does not expose an inbound management listener. A bounded pool of outbound
sessions provides concurrent control/log/terminal transport without opening
additional inbound ports.

## Kubernetes / OpenShift

Kubernetes/OpenShift normally use their native authenticated APIs and do not require this connector on worker nodes.

## Running the connector

The executable entry point is:

```text
cmd/baseharbor-node-connector
```

Required runtime configuration:

```text
--core HOST:PORT
--tenant-id CORE_TENANT_UUID
--target-id TARGET
```

The node ID defaults to the local hostname. The connector detects Docker or
Podman locally and binds that detected runtime into its authenticated node
identity.

Existing identity material defaults below the connector state root:

```text
identity/node.crt
identity/node.key
identity/ca.pem
```

If identity material is incomplete, startup fails closed unless an explicit
HTTPS bootstrap endpoint is configured. Bootstrap requires a pinned bootstrap
CA and a private Core-issued JSON authorization file. The connector generates its private Ed25519 key
locally; the private key never leaves the host.

Example initial enrollment:

```bash
baseharbor-node-connector \
  --core core.example:9443 \
  --tenant-id 11111111-1111-4111-8111-111111111111 \
  --target-id edge-a \
  --bootstrap-url https://core.example:9444/v1/node-enrollment \
  --bootstrap-ca /etc/baseharbor/bootstrap-ca.pem \
  --bootstrap-authorization-file /run/credentials/baseharbor-bootstrap-authorization.json
```

The Core-issued token/nonce grant is consumed once by Core; the local authorization file is removed after successful enrollment by default.

Configuration can also be supplied through the corresponding
`BASEHARBOR_CONNECTOR_*` environment variables. Secret values themselves are
not accepted as flags; bootstrap uses an authorization file path.

## Current state

Target Access v1 is implemented with:

- typed bounded runtime operations;
- authenticated capability/version negotiation;
- TLS 1.3 mTLS with explicit peer identity;
- CSR enrollment and certificate installation; current trust and revoked serial checks at handshakes, before writes and after inbound frames;
- traversal-safe artifact staging with SHA-256 verification;
- bounded log streaming with retained cursors; PTY streams reject replay and reattachment;
- outbound-only concurrent session pooling;
- an executable connector daemon.

The Core/control-plane CA issuance and enrollment HTTP endpoint remain a
BaseHarbor Core responsibility. Kubernetes/OpenShift continue to use their
native authenticated API access path rather than this connector.

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

Node Connector candidate: `bceafc43befc6f52f5da56c796519edeaafe80b4` ([PR #5](https://github.com/mcpdev80/baseharbor-node-connector/pull/5)).
Core candidate under active development: `49a2fab76079b98b5697ba9f556abb6e6c066cac` ([Core PR #837](https://github.com/mcpdev80/baseharbor/pull/837)).
Console candidate: `de4b6fd436d70b7d03d38069b1873e23305580ad` ([Console PR #4](https://github.com/mcpdev80/baseharbor-console/pull/4)).

Connector package-local `go test ./... -count=1`, `go vet ./...` and formatting passed on the cited Connector commit ([HF evidence](https://huggingface.co/jobs/ThunderHawk1080/6ac7eb7e095c5780892fc9f9)). Final joint-sha remote Docker/Podman enrollment, node reconnect, replay rejection, rotation/revocation, resource ownership, lifecycle cleanup and Console OIDC/RBAC acceptance remain required. Passing v0.4.23 integration evidence against a different Core SHA does not qualify this candidate.

This section is a candidate matrix, **not** a release pin or a claim of final integrated acceptance.
