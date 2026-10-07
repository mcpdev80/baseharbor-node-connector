# Target Access v1

The Node Connector implements one optional BaseHarbor Target Access Provider.

Normative boundary:

```text
BaseHarbor Core
    |
    | authorized typed runtime operation
    v
Target Access Provider
    |
    | authenticated encrypted transport
    v
Node Connector
    |
    v
Docker / Podman / systemd / Quadlet
```

The connector does not own Application intent, desired state, placement, policy,
authorization or reconciliation.

## Versioning

Wire contract:

```text
baseharbor.target-access/v1
protocol_version = 1
```

Every request carries:

- request ID;
- required Core execution correlation and absolute UTC deadline;
- Target identity;
- one allowlisted typed operation;
- issuance timestamp;
- operation-specific structured payload.

Requests outside the accepted clock-skew window fail closed.

There is no generic host shell, `runtime_command`, `workspace_command` or
arbitrary command operation.

## Node identity

The connector binds one stable node identity to one configured BaseHarbor
Target and detected runtime.

```text
node_id
target_id
runtime
certificate identity
instance_id (optional)
```

The certificate identity is opaque to the wire contract. Current mTLS support
matches an explicitly configured URI SAN or DNS SAN. Enrollment may later
choose the concrete identity naming scheme without changing Target Access v1.

The runtime in node identity must match the runtime detected on the connector
host.

## Capability negotiation

Capabilities are returned only from the real connector/runtime projection.

Docker does not advertise Podman-only Quadlet operations. Callers must use
capability discovery rather than branch on provider names.

Negotiation occurs only after transport authentication in the eventual network
transport. The transport-neutral capability model itself contains no
credential material.

## mTLS baseline

`TLSFiles` defines the connector-side security boundary:

- TLS 1.3 minimum;
- client and server certificate support;
- explicit trust bundle;
- explicit expected peer identity;
- certificate-chain verification;
- URI/DNS SAN peer-identity binding;
- no plaintext fallback;
- certificate/key and trust material are loaded from files rather than embedded
  in the wire contract;
- certificate/key and trust files are re-read during new handshakes, permitting
  rotation without changing Target or Node identity.

The final transport will use this TLS configuration. The v1 semantic contract
does not freeze HTTP, gRPC, WebSocket or another framing mechanism.

## Operations

Observation:

```text
runtime.detect
runtime.resource.list
runtime.resource.inspect
runtime.image.list
runtime.volume.list
runtime.network.list
runtime.logs.read
runtime.metrics
connector.health
```

Bounded realization:

```text
runtime.image.pull
runtime.volume.ensure
runtime.volume.remove
runtime.network.ensure
runtime.network.remove
runtime.container.start
runtime.container.stop
runtime.container.restart
runtime.container.remove
runtime.compose.apply
runtime.compose.destroy
runtime.quadlet.apply
runtime.quadlet.remove
runtime.quadlet.enable
runtime.quadlet.disable
runtime.exec
```

`runtime.exec` remains container-scoped and requires explicit argv. It is not
a host shell.

Compose inputs remain confined to the connector staging root and reuse the
existing traversal/symlink-escape protection.

## Audit correlation

`request_id` identifies the transport request. `correlation_id` carries the
BaseHarbor Core audit/execution correlation through the connector without
giving the connector ownership of authorization or audit policy.

## Remaining external responsibility

The connector side of bootstrap and concurrent outbound session handling is now
implemented. The certificate issuance authority and enrollment endpoint remain
a BaseHarbor Core/control-plane responsibility rather than connector-owned
state.

Connection direction and ownership are fixed for the connector product: the
connector dials BaseHarbor Core outbound and does not expose an inbound
management listener.


## Enrollment

Enrollment is a separate transport-neutral contract:

```text
baseharbor.target-access-enrollment/v1
```

The connector generates its private key locally and sends only a signed PKCS#10
CSR plus tenant/Node/Target/runtime identity and the Core-bound anti-replay nonce.

The enrollment response contains the assigned Node identity, certificate chain,
trust bundle and certificate expiry. Private-key material is never returned by
or embedded in the enrollment response.

The bootstrap client uses a pinned bootstrap trust bundle, HTTPS with TLS 1.3,
normal X.509 hostname verification plus explicit expected Core URI/DNS SAN
identity, and a Core-issued token/nonce/expiry JSON authorization stored in a private local file. The
connector creates an Ed25519 private key locally when none exists, sends only a
signed CSR, uses the Core-bound nonce unchanged and requires the response to echo it,
binds the returned Node/Target/runtime/identity to the request, verifies the
issued certificate and chain, installs certificate/trust material atomically,
and removes the consumed bootstrap authorization file after successful installation by default.

Redirects are not followed during enrollment, preventing bootstrap credentials
from being forwarded to another endpoint. The CA/issuance backend itself
remains a Core/control-plane responsibility and may evolve independently of the
Target Access semantic contract.

## Rotation and revocation

Certificate, private-key and trust-bundle files are re-read for new TLS
handshakes. A trust bundle may contain overlapping old/new roots during CA
rotation.

An optional reloadable revoked-serial file fails closed for explicitly revoked
peer certificates. Certificate validity and chain verification are enforced by
the X.509 verifier on every new connection.

## Artifact bundles

`artifact.bundle.stage` transfers a typed bundle into:

```text
<staging-root>/bundles/<bundle-id>/...
```

Each file requires a SHA-256 digest. Writes are atomic and reject:

- absolute paths;
- bundle-relative traversal;
- traversal outside the staging root;
- symlink parent components;
- symlink target replacement;
- duplicate logical paths;
- hash mismatch.

Compose realization continues to consume only staged paths.

## Stream semantics

Target Access v1 defines transport-neutral stream semantics for logs and
terminal sessions:

- stable stream IDs;
- audit correlation IDs;
- monotonically increasing event sequence;
- resume cursor using the last accepted sequence;
- typed ready/data/resize/exit/error/end events;
- bounded log options;
- terminal sessions require explicit argv and remain resource-scoped.

The session framing is now implemented as bounded length-prefixed JSON inside
the authenticated TLS session.

Log streams use the existing bounded Docker/Podman log operation and can follow
live output. Terminal streams use a real Unix PTY around bounded
`docker|podman exec -i -t ...`; they never expose a host shell. Input data and
resize events are resource-scoped, and process termination returns a structured
exit event. Windows advertises terminal capability as unavailable.

`resume_after` is implemented for log streams with a bounded in-memory replay
window. A reconnect first replays retained events after the supplied sequence
and then restarts runtime log following with a five-second time overlap from
the last observed event. This provides at-least-once delivery: duplicate log
records are possible across reconnect, but gaps are avoided where the runtime
retains those logs. Expired cursors fail closed.

Live PTY sessions deliberately cannot be reattached after transport loss.
Interactive terminal state is terminated rather than silently attaching a new
client to an unknown process state. This is the v1 resume policy for terminal
streams.


## mTLS session core

The connector now provides a concrete authenticated session core over an
already-established `net.Conn`.

The session:

- upgrades the connection to TLS 1.3 mutual authentication;
- verifies the certificate chain and configured peer URI/DNS SAN;
- binds the remote `Hello.node.identity` to the authenticated certificate identity;
- negotiates Target Access contract/protocol versions only after mTLS succeeds;
- uses bounded length-prefixed JSON frames;
- rejects oversized/zero-length frames;
- uses complete writes and strict unknown-field decoding;
- carries requests, responses and dedicated stream frames.

The product topology is outbound-initiated from the Node Connector to
BaseHarbor Core. The connector does not expose an inbound management listener.
This reduces firewall/NAT requirements and attack surface while keeping the
session framing independent from the semantic Target Access contract.

`RunOutboundControl` remains the single-session compatibility entry point.

For production concurrency, `RunOutboundPool` maintains a bounded set of
outbound-only authenticated sessions (four by default, maximum 32). Every
session is equivalent: after authenticated version negotiation its next frame
is strictly classified as either a typed control Request or a StreamOpen.
A session carrying a log or terminal stream remains occupied by that stream,
while the remaining sessions continue serving control operations or additional
streams. This avoids head-of-line blocking without changing the Target Access v1
wire objects or adding an inbound management listener. Each pool worker
reconnects with bounded exponential backoff.

`connector.capabilities` is an authenticated typed operation and returns the
actual runtime capability projection after session establishment.

## Identity renewal installation

Enrollment/renewal installation additionally:

- verifies the enrolled certificate SAN identity;
- proves the certificate public key matches the local private key;
- verifies the new certificate against the supplied trust bundle;
- refuses response expiry beyond certificate validity;
- atomically replaces certificate/trust files;
- rejects symlinked identity directories.

Private key material remains local throughout enrollment and renewal.


## Enrollment certificate admission

Installation requires a single client-only leaf certificate bound to the locally
held key and expected node URI. CA leaves, server/dual-purpose usage, unexpected
SANs, mismatched validity and additional PEM material fail before identity files
are changed. Trust files contain only CA certificates. CSR input is one signed
PKCS#10 request within 64 KiB; prefixes, trailing material and multiple requests
are rejected. This source boundary does not qualify the pending Core enrollment
endpoint or remote lifecycle integration.

Canonical acquisition and bootstrap JSON/tenant requirements follow the
[pinned Core wire boundary](../README.md#pinned-core-wire-and-bootstrap-binding).
Source checks are separate from exact-ref production/runtime qualification.

## Source-bound Quadlet completion observation

`runtime.quadlet.verify-completion` is an authenticated, read-only capability for
Linux Podman with a live user systemd manager. Its payload requires `name`
(a `.container` unit), the exact unresolved `content`, and `project_directory`
(an immutable `bundles/.object-<hex>` publication). It cannot select host paths,
start units or supply an `enable` flag. Normal peer, Target and capability checks
apply; the observation does not admit or replay a mutation.

The Node verifies the published bundle, current unit and native resource ownership,
resolved source digest, protected activation receipt and current Linux boot.
Native successful process exit must follow that source's recorded activation
and have settled unit state. Failed, unstarted, altered, removed and stale units
fail closed. An absent container alone is never successful completion evidence.

Success returns `name`, `project_directory`, `content_sha256` (SHA-256 of the
unresolved request content) and `completed: true`. Core revalidates all four
fields against its scoped immutable project before accepting the observation.
This primitive does not itself qualify the complete remote Application lifecycle
or authorize enabling unqualified completion-dependency realization.

Published Quadlet apply accepts optional `autostart`. Core uses `enable: true,
autostart: false` for completion-dependent graphs: the node starts the exact
published owned unit and clears WantedBy, RequiredBy, UpheldBy and Alias target
activation. A later boot therefore requires Core to verify init completion again
before it starts the dependent. Omitting `autostart` retains ordinary apply
behavior; specifying it requires `project_directory`. This is a bounded activation
instruction, not application policy or a new node authority. Target membership
checks do not claim an actual reboot or full Application lifecycle qualification.
