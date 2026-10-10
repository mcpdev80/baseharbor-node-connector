# Release integration

## BaseHarbor v0.4.24 compatibility

The v0.4.24 code candidate has completed joint native Docker and rootless Podman acceptance and the full Core pre-release evidence check. Publication remains pending. `integration-candidate.json` records the immutable tested code dependencies; documentation changes do not replace these source bindings.

The accepted workflows include Core setup, managed Node enrollment, outbound mTLS, renewal/revocation and reconnect, remote application plan/apply/status/doctor/destroy, real Console OIDC/RBAC, events, logs, terminal and credential/CA rotation. Core remains authoritative for state, policy, provider placement and reconciliation. Kubernetes/OpenShift use their native APIs and do not require a Node Connector.

See [Core release status](https://github.com/mcpdev80/baseharbor/pull/837) and the [Core documentation](https://mcpdev80.github.io/baseharbor/). Source tests and preview fixtures remain separate from native integration acceptance.

## Running qualification

Use the existing release-integration workflow with an exact reviewed source candidate. Repository-local checks do not substitute for real Core, OIDC, browser and native runtime journeys. Both Docker and Podman jobs must produce authenticated source-bound manifests with successful cleanup.

## Support boundaries

Use a version-matched Core, Console and Node Connector. CLI and Console share Core authorization and lifecycle operations; the Connector supplies bounded authenticated transport. Live access fails closed when Core or the selected Target is unavailable. Existing legacy resources and foreign data remain protected.

Cross-host failover, application-scoped PostgreSQL HA and unqualified major-version upgrades are not claimed. Future onboarding, AI-assisted Console and additional platform work are outside this release.
