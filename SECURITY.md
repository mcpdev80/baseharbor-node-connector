# Security Policy

BaseHarbor Node Connector carries authenticated remote Target Access operations and may transport runtime control, logs, metrics, terminal streams and deployment artifacts. Security reports are treated as private until a fix and disclosure plan are ready.

## Reporting a vulnerability

Do **not** open a public issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting / Security Advisory flow for this repository.

Useful information includes:

- affected Connector version or commit;
- affected BaseHarbor Core version or commit;
- affected runtime (Docker or Podman);
- reproduction steps;
- expected and observed behavior;
- security impact;
- logs with all secrets, certificates, tokens and private material removed.

Never include bootstrap tokens, private keys, client certificates, recovery material or live credentials.

## Security boundaries

The Node Connector must preserve these boundaries:

- it is not a BaseHarbor control plane;
- it is not a Runtime Provider;
- it does not own desired state, placement, policy or authorization;
- it exposes no unauthenticated inbound management listener;
- BaseHarbor-managed remote access uses mutually authenticated TLS;
- plaintext fallback is forbidden;
- peer identity is verified before capability negotiation;
- expired, revoked or otherwise invalid identities fail closed;
- private keys remain local and protected;
- deployment staging rejects traversal and symlink escape;
- terminal/exec remains bounded to explicit authorized Target Access operations;
- no unrestricted generic host shell is exposed;
- Kubernetes/OpenShift normally use their native authenticated APIs rather than this connector.

## Supported versions

The Connector is currently pre-v1. Security fixes are applied to the latest development/released line unless a specific issue requires a backport.

## Relationship to BaseHarbor Core

Core remains authoritative for enrollment, CA/trust, authorization, Target/runtime binding, ownership, reconciliation and audit policy. A Connector must never infer authority from network reachability or from a trusted CA alone.
