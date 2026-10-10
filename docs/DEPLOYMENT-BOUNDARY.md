# Deployment boundary

## BaseHarbor v0.4.24 compatibility

The v0.4.24 code candidate has completed joint native Docker and rootless Podman acceptance and the full Core pre-release evidence check. Publication remains pending. `integration-candidate.json` records the immutable tested code dependencies; documentation changes do not replace these source bindings.

The accepted workflows include Core setup, managed Node enrollment, outbound mTLS, renewal/revocation and reconnect, remote application plan/apply/status/doctor/destroy, real Console OIDC/RBAC, events, logs, terminal and credential/CA rotation. Core remains authoritative for state, policy, provider placement and reconciliation. Kubernetes/OpenShift use their native APIs and do not require a Node Connector.

See [Core release status](https://github.com/mcpdev80/baseharbor/pull/837) and the [Core documentation](https://mcpdev80.github.io/baseharbor/). Source tests and preview fixtures remain separate from native integration acceptance.

## Historical implementation and qualification records

The records below describe earlier implementation stages. Their pending-coverage statements describe those stages; the current v0.4.24 acceptance scope is stated above. API and ownership restrictions continue to apply.

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

New immutable publications also commit file permissions. Core-approved native
bind files may be readable by their unprivileged container user while staging,
object and parent directories remain owner-only. Runtime environments use 0600.
Publication rejects unsupported writable or privileged modes, and execution
rechecks protected ancestors and exact committed file modes. Existing version-1
owner-only objects remain valid; loosening their permissions is rejected.

The native Docker qualification now exercises Core-generated PostgreSQL TLS
material, UID 70, TLS-verified SELECT 1, receipt restoration/repair and explicit
owned volume reset. Rootless Podman now passes generated SQL as described below;
its explicit data reset and the complete Core Application lifecycle remain
outstanding. This narrower proof is not release eligible.

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
`6ab378bbff51cfbefecb9633a08f440cf4372ade`, with actual OpenBao 2.7.0, isolated
PostgreSQL storage/admission and either Docker or rootless Podman. It exchanges
a persisted one-use Core grant over verified HTTPS, opens outbound mTLS, retains
the local node key during explicit renewal, verifies live CA overlap and old-root
retirement, and denies invocation/reconnection after persisted revocation.
Native inventory and one bounded typed exec use an exact owned runtime fixture.

The current harness obtains real access tokens from the reference Keycloak
image, verifies OIDC discovery/JWKS over trusted HTTPS, resolves the operator's
persisted tenant membership and creates initial/renewal grants through Core's
protected HTTP handler. Missing, expired, wrong-audience and viewer tokens, and
a foreign Target selection, must be denied before grant creation. Password
grant is confined to disposable test accounts; the product login flow is unchanged.

The expanded native qualification passed on both Docker and rootless Podman in
run `37586292164` against Core `49e0ef0c4dbc3c9eedac198f238d116f051496e2`
and Connector `4f806267c8982585d3e6cb3f2d7dd8182e687b06`. Earlier receipts using
direct grant creation remain outside the operator proof. The
receipt still excludes the Core-authoritative Application lifecycle and release
approval. A successful test must not be promoted to the full remote-target gate.

The managed native slice also exercises the Core-bound immutable project adapter
through this production enrollment: exact digest-verified staged bytes, Docker
Compose or rootless Podman Quadlet apply, observed running state, explicit
repair, destroy and foreign-resource preservation. This realizes already
authorized project decisions; the complete Core Application planning, provider
placement and secret binding journey remains a separate required release proof.

Published Quadlet apply can bind its exact content to an immutable staging
publication. Read-only TLS binds and owner-only environment files resolve only
on the selected Node; Core host paths and build inputs are not transferred.
Native name collisions require protected realization ownership and matching
runtime labels. The Core graph adapter first publishes the complete graph without starting
containers, then activates dependencies before their dependents. Cycles and
invalid selections are refused before the first mutation; interrupted operations
are not replayed. Destruction reverses dependency order and preserves provider
data. The current native harness additionally verifies a two-container dependency
graph after enrollment, including exact commitment restoration, repair and
foreign-resource preservation. Its latest source needs its own native result.
Actual generated SQL graphs passed on Docker and rootless Podman in the run
above, including native UID 70, TLS SELECT 1 and immutable repair. Ordinary
Podman destroy preserved owned provider data; explicit Podman reset remains
unqualified. This primitive does not qualify the full Application engine or
make a release-eligible receipt.

The newer pinned Core adds protected durable deployment-project commitments and
preserves them through pending/applied/observed transitions. This subsequent
source needs its own native rerun; the earlier successful receipt does not
approve a newer source or the full Application lifecycle.

Ordinary Quadlet removal retains immutable realization history outside generator search paths. Reapply of the exact unchanged network/volume source can reuse this protected history only when the active artifact is absent and native project labels still match. Foreign active units, changed source, altered permission commitments and missing receipts remain denied. Native ownership inspection and unit realization share the manager's operation lock. The new destroy/reapply SQL qualification must pass before this slice is considered natively qualified; explicit Podman data reset and the full Application journey remain separate requirements.

Application resource preflight requests fresh Linux node-memory evidence through `connector.health` on the exact authenticated Tenant/Target/Node/runtime scope. Runtime-info total memory is not treated as free capacity. Missing, stale, changed-runtime or inconsistent evidence fails closed; the Core host is not a fallback. This bounded resource proof does not qualify cluster quotas, VM/cgroup limits, or the complete Application lifecycle. Memory PSI remains unavailable in this projection and is reported as such. The new native run must qualify this source before its node-memory receipt flag is accepted.

Managed project-unit removal independently rechecks live native ownership before stopping the generated service or deleting its protected unit. A retained own unit receipt cannot authorize a container, network or volume that has since been replaced with foreign project labels. Rejected removal preserves both the native resource and the protected unit. Ordinary data retention and explicit data-reset qualification remain distinct.

The enrolled native harness also verifies Core completion observations against
actual retained containers: successful exit 0, failure exit 17, never-started,
running and removed containers are distinguished. Native ownership labels and
exit timestamps are checked over the authenticated Node session. This does not
qualify Quadlet init realization or the complete Application lifecycle.

The local Quadlet manager can observe a loaded unit only after matching its
protected ownership receipt and exact published Core bundle content, including
resolved Node file bindings. The loaded systemd SourcePath must match the owned
unit. Bounded native exit/start timestamps distinguish evidence from mere
inactivity. Transport exposure and native init-unit qualification remain pending.

Published container activation now retains a protected receipt for the exact
resolved source digest, current Linux boot identity and a monotonic activation
lower bound. Completion requires native successful exit evidence after that
bound on the same boot; old success cannot qualify a changed or unexecuted
publication. Missing, altered or foreign receipts are denied. Ordinary removal
cleans the current receipt while retained immutable ownership history stays
outside generator search paths. The focused native manager test must qualify
this source independently; the completion observation is still not exposed over
Target Access, and the full Core Application lifecycle remains unqualified.

Managed network-unit removal stops the exact owned unit, rechecks its live native project labels and removes only that named network without force. Quadlet stop alone normally retains networks. A network with live consumers is preserved, and the protected unit remains available for an explicit retry. Volumes remain retained until a separate explicit owned data reset. Successful removal verifies native network absence before deleting the unit source.
