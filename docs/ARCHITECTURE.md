# Architecture

Hard rule:

```text
Runtime Provider != Target Access Provider
```

The connector is one optional Target Access Provider implementation.

Console, MCP and other clients never talk to this component directly:

```text
Console / CLI / MCP / HTTP
          |
          v
     BaseHarbor Core
          |
          v
    Runtime semantics
          |
          v
   Target Access Provider
          |
          v
    Node Connector
```

This keeps operator authorization, policy, safety, ownership and audit in BaseHarbor Core.
