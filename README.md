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
CA and one-time token file. The connector generates its private Ed25519 key
locally; the private key never leaves the host.

Example initial enrollment:

```bash
baseharbor-node-connector \
  --core core.example:9443 \
  --target-id edge-a \
  --bootstrap-url https://core.example:9444/v1/node-enrollment \
  --bootstrap-ca /etc/baseharbor/bootstrap-ca.pem \
  --bootstrap-token-file /run/credentials/baseharbor-bootstrap-token
```

The bootstrap token is consumed after successful enrollment by default.

Configuration can also be supplied through the corresponding
`BASEHARBOR_CONNECTOR_*` environment variables. Secret values themselves are
not accepted as flags; bootstrap uses a token file path.

## Current state

Target Access v1 is implemented with:

- typed bounded runtime operations;
- authenticated capability/version negotiation;
- TLS 1.3 mTLS with explicit peer identity;
- CSR enrollment, certificate renewal and revocation handling;
- traversal-safe artifact staging with SHA-256 verification;
- log and PTY streaming with bounded reconnect/resume semantics;
- outbound-only concurrent session pooling;
- an executable connector daemon.

The Core/control-plane CA issuance and enrollment HTTP endpoint remain a
BaseHarbor Core responsibility. Kubernetes/OpenShift continue to use their
native authenticated API access path rather than this connector.
