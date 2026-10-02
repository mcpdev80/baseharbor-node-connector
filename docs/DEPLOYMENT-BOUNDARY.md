# Deployment boundary

The Node Connector can realize deployments for remote Docker/Podman targets, but it never decides deployment intent.

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

All project directories, Compose files and optional env files are resolved through the staging-root guard. Existing symlinks are evaluated and an artifact that resolves outside the staging root is rejected.

This lets a future #769 transport transfer a bounded deployment bundle without granting arbitrary host filesystem access.

The wire transfer/enrollment protocol remains intentionally undefined until BaseHarbor #769 finalizes the Target Access Provider contract.

## No generic runtime-command API

The legacy agent's generic `runtime_command` and `workspace_command` channels are deliberately not exposed.

BaseHarbor invokes named typed capabilities instead.
