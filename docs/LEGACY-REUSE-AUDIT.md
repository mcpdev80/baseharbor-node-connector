# Legacy agent reuse audit

Source reviewed: `mcpdev80/baseharbor-container-manager`.

## Reused concepts / code patterns

### Runtime detection
The old `pkg/containerruntime` Docker/Podman detection is retained in a smaller connector-local detector.

### Container inventory and metrics
The old container list combines:

- `runtime stats --no-stream`
- `runtime ps -a`
- Compose project/service labels
- Podman Quadlet/systemd labels

That useful observation logic is retained.

### Logs and inspect
Bounded `logs` and `inspect` operations are retained behind typed adapter methods.

### Exec
The useful timeout/workdir/environment handling is retained, but the new connector accepts an explicit argv vector. It does not parse a space-separated command string and never invokes a shell implicitly.

### Terminal
The old implementation proved useful concepts:

- explicit session identity
- PTY resize events
- ready/data/exit/error event lifecycle
- hard/idle timeout concepts
- container terminal rather than generic host shell

The new repository retains the transport-neutral request/event model only. The wire transport and identity binding wait for BaseHarbor #769.

### Health / heartbeat
The old heartbeat fields for runtime version, OS/arch, CPU/memory and container/image counts are retained as useful observation concepts.

## Explicitly rejected legacy architecture

Do not port:

- generic `runtime_command` or `workspace_command` remote jobs
- agent self-update jobs as a privileged generic job channel
- Traefik reconciliation
- workspace/Git deployment
- OpenBao node tokens
- persisted broad bearer agent token model
- manager-local agent/node source of truth
- direct browser/Console-to-agent terminal path
- unauthenticated or separately exposed terminal management ports
- generic host shell
- connector-owned policy/authorization
- connector-owned BaseHarbor application/provider state

## Security improvements over legacy

The new executor:

- uses `exec.CommandContext`, never a shell;
- does not log command output or environment values;
- keeps execution behind typed bounded operations;
- validates resource/environment inputs;
- relies on BaseHarbor Core for authorization/policy;
- does not define an enrollment or network protocol before #769.
