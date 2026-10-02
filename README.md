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

An outbound-initiated connection may be used where appropriate to reduce attack surface and simplify NAT/firewall traversal, but the transport is intentionally not frozen here.

## Kubernetes / OpenShift

Kubernetes/OpenShift normally use their native authenticated APIs and do not require this connector on worker nodes.

## Current state

This repository is intentionally architecture-only until the Target Access Provider contract in BaseHarbor #769 is implemented/finalized. Do not invent a private connector protocol ahead of the Core contract.
