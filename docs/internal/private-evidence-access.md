# Private evidence access preflight

The adjacent `v0.4.23-private-access-pins.json` is an access-only source snapshot. Copy its entire JSON into the public Core repository's Actions secret `BASEHARBOR_PRIVATE_EVIDENCE_PINS`. It contains private source identities, so keep it out of public files, logs and artifacts.

Set the separate Actions secret `BASEHARBOR_PRIVATE_EVIDENCE_TOKEN` to an expiring token limited to Contents read and Actions read on the private Console and Node Connector repositories. Enter credentials directly in GitHub; do not add them to this repository or chat.

Run the existing public Core Source Preflight on `runtime-validation/source-preflight/v0.4.23-private-evidence-access` after provisioning. That job checks exact source metadata and Actions access and always reports `release_approved: false`.

These source pins do not establish full Application qualification. The Connector source remains a managed enrollment/project primitive producer, not a trusted full Application release producer. Its release-integration workflow is still required. Final source pins must be reviewed and replaced after implementation and fresh qualifications against the final public Core and Demo candidates; then all 63 mandatory gates must pass before pre-release.
