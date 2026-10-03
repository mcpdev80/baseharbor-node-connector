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
- optional audit correlation ID;
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

## Still intentionally open

Target Access v1 does not yet define:

- enrollment workflow;
- certificate issuance authority;
- revocation distribution mechanism;
- network framing/connection direction;
- artifact bundle upload framing;
- log stream framing;
- PTY stream framing;
- reconnect/resume behavior.

Those build on this contract without reopening Runtime Provider semantics.


## Enrollment

Enrollment is a separate transport-neutral contract:

```text
baseharbor.target-access-enrollment/v1
```

The connector generates its private key locally and sends only a signed PKCS#10
CSR plus Node/Target/runtime identity and an anti-replay nonce.

The enrollment response contains the assigned Node identity, certificate chain,
trust bundle and certificate expiry. Private-key material is never returned by
or embedded in the enrollment response.

The bootstrap authentication mechanism and certificate authority remain outside
Target Access v1 and may evolve independently.

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

This does not yet select the concrete network framing or implement the session
transport.


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

Connection establishment/direction remains separate. The same session can be
used on an inbound listener or an outbound-initiated tunnel without changing
the Target Access semantic contract.

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
