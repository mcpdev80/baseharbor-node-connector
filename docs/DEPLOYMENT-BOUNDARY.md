# Deployment boundary

The Node Connector can realize deployments for remote Docker/Podman targets, but it never decides deployment intent.

Configure `--runtime docker` or `--runtime podman` (or
`BASEHARBOR_CONNECTOR_RUNTIME`) to bind startup to the enrolled Target's engine.
An unavailable explicit selection fails closed and never probes another engine.
Omitting the selection preserves detection for existing installations; the
authenticated Core session still rejects a different enrolled runtime.

Captured process stdout and stderr are each limited to 256 KiB. Overflow
cancels the producer and returns a typed failure without a partial successful
result. Continuous output uses bounded stream frames and reader backpressure.

## Control flow

```text
baha plan / baha apply
          |
          v
BaseHarbor Core
  - intent
  - provider placement
  - policy
  - authorization
  - ownership
  - reconciliation
          |
          v
typed Target Access operation
          |
          v
Node Connector
          |
          +--> Docker / Podman lifecycle
          +--> Compose realization
          +--> Podman Quadlet realization
```

## Connector responsibilities

The connector may:

- detect Docker/Podman;
- pull a specific image;
- start/stop/restart/remove a specific runtime resource;
- ensure/remove a named network or volume;
- apply/destroy a Compose project from already staged artifacts;
- atomically write and enable/disable a permitted Quadlet;
- inspect/list/log/exec against explicitly selected resources;
- report runtime health and capabilities.

## Core responsibilities

The connector must not decide:

- which provider to choose;
- which image/version should be deployed;
- where an application should be placed;
- whether an operation is authorized;
- whether a managed resource may be destroyed;
- secret source-of-truth or secret generation;
- application/deployment desired state;
- reconciliation strategy.

## Staged artifacts

Compose deployment uses an explicit connector staging root.

Every bundle member is validated before a new private object is written through
Go's confined filesystem root. Publication uses an atomic no-replace hard link
to the complete manifest. Existing bundle IDs, files and symlinks survive failed
or concurrent publication. Cancellation removes only the new uncommitted object;
an interrupted process may leave an orphan, which cannot be deployed.

Compose accepts only a committed bundle directory and members from that same
bundle. It rechecks every digest before invoking the engine. Returned paths are
opaque artifact references; Core uses them rather than guessing a directory.

Quadlet realization receipts retain immutable content outside the generator's
search paths. Existing unit/drop-in artifacts without a verified matching inode
and digest are foreign and cannot be overwritten, stopped or removed. Generated
units use native `[Install]` drop-ins and `systemctl --user start/stop/restart`,
not `systemctl enable` on generated services. The live capability requires a
reachable Linux systemd user manager. These receipts describe realization only;
Core retains desired state, policy and authorization authority.

The canonical public wire package defines transfer, enrollment and native
Quadlet names. Source checks and primitive runtime probes do not qualify the
full production enrollment/ownership/application/browser release requirements.

## No generic runtime-command API

The legacy agent's generic `runtime_command` and `workspace_command` channels are deliberately not exposed.

BaseHarbor invokes named typed capabilities instead.

Canonical acquisition and bootstrap JSON/tenant requirements follow the
[pinned Core wire boundary](../README.md#pinned-core-wire-and-bootstrap-binding).
Source checks are separate from exact-ref production/runtime qualification.

## Native managed enrollment qualification

The opt-in `runtime-validation/enrollment/**` push runs the separately built
Connector against the exact public Core harness at
`fa9d504afdef46e93c7a2f2d5a578db408ae6c40`, with actual OpenBao 2.7.0, isolated
PostgreSQL storage/admission and either Docker or rootless Podman. It exchanges
a persisted one-use Core grant over verified HTTPS, opens outbound mTLS, retains
the local node key during explicit renewal, verifies live CA overlap and old-root
retirement, and denies invocation/reconnection after persisted revocation.
Native inventory and one bounded typed exec use an exact owned runtime fixture.

The Core grant is created directly by the production authority in this fixture;
this does not qualify an operator OIDC authorization journey. The receipt also
explicitly excludes the Core-authoritative Application lifecycle and release
approval. A successful test must not be promoted to the full remote-target gate.
