# execbound-protocol

The provider protocol ExecBound's server and its connectors share: the action catalog, the provider command the server freezes and a connector receives, the signed journal and connector record a connector returns, the checkpoint report an external executor sends and the signed outcome formats it can carry, and the `Connector` interface. It imports nothing from the server, so a connector can be written against it alone.

Apache-2.0. The server that enforces it is AGPL-3.0-only and lives in the same repository.
