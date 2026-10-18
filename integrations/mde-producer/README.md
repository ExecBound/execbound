# execbound-mde-producer

Microsoft Defender for Endpoint as an ExecBound security signal producer. Each cycle it reads every covered host's risk score with a read-only application and posts it to ExecBound as an `execbound.security-signal.v1` envelope. It maps nothing, decides nothing and is never called by ExecBound. What a risk score means is your mapping in the bundle ([Security signals](../../docs/SIGNALS.md)); the reviewed table for this producer is [`scenario/thresholds.json`](scenario/thresholds.json).

## What it needs

- An Entra application with `WindowsDefenderATP` `Machine.Read.All` and nothing else, admin-consented. Its `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` go in a file only you can read (mode 600).
- A producer token from `execbound signal-source-create`, registered without `--attests-liveness`. The machines API has no field that shows a sensor is still reporting, so the quietest risk score must map to `no_detection`, never `clean`.
- The ExecBound resource each host stands for.

## Configuration

```json
{
  "gateway": "https://gateway.example.com",
  "token_file": "producer.token",
  "defender_env": "defender.env",
  "account_id": "<the endpoint account's id>",
  "provider": "mock_crowdstrike",
  "resource_type": "endpoint",
  "hosts": [
    {
      "azure_resource_id": "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.Compute/virtualMachines/<vm>",
      "provider_id": "<the ExecBound resource's provider id>"
    }
  ],
  "interval_seconds": 60
}
```

- A host is matched to the one Defender machine whose `vmMetadata.resourceId` equals its `azure_resource_id`, ignoring case.
- A host with no single match gets no envelope, and its decisions fail closed until it has one. That includes a newly onboarded Windows host, which has no `vmMetadata` until its first full report.
- `http://` is accepted only for a loopback gateway.
- The interval must leave room under ExecBound's 300-second freshness, so it can be at most 240 seconds.
- File paths are relative to the configuration file. The secret files must be private.

## Run it

Install this standalone package with Python 3.11 or later on Linux or another POSIX system:

```bash
python -m pip install ./integrations/mde-producer
chmod 600 defender.env producer.token
```

The file permission check requires owner-only POSIX permissions. On Windows, run the producer
inside WSL and keep secret files in its Linux filesystem, outside the protected agent's reach.

```bash
execbound-mde-producer run --config producer.json
```

It logs one JSON line of counts per cycle to standard error. It stops with exit status 2 when the gateway refuses its token; rotate the token with `execbound signal-source-rotate`.

Use `--once` for a single cycle: exit 0 means every configured host was recorded, exit 1
means a read, match or post was unsuccessful, and exit 2 means configuration or producer
authentication was refused. Restart after rotating either credential file. Each cycle posts
once per matched host; a failed post is counted, with a new observation on the next cycle.
The client never follows redirects or uses environment proxy settings. Defender pagination
is limited to 20 pages and 8 MiB per page; integer `Retry-After` advice is capped at one hour.

A missing match stops new observations. An earlier accepted observation remains usable until
its configured freshness deadline (300 seconds by default); silence does not revoke it early.
The machines API reports a stored risk score, not proof that a sensor is still reporting.
Register this source without liveness and keep quiet scores mapped to `no_detection`.

A live lab trial on October 1, 2026 UTC read two Defender hosts through this producer into a
local ExecBound gateway on PostgreSQL. `None` required review, `Medium` allowed the mock
isolation, hard deny still won, and missing, stale or revoked evidence prevented dispatch.
An unexpired approval submitted after source revocation was invalidated. Console evidence
and offline replay were also checked. The [integration register](../../docs/INTEGRATIONS.md)
records this scope as `platform-validated`.

On October 3, 2026 a follow-up run recorded the live `Medium`-to-`None` transition: once a
resolved alert dropped the score, the same request went to review. The same day, the
committed Tines governed-action story sent the baseline, quiet and compromised requests to the
hosted gateway on a synthetic tenant, with this producer posting to it over HTTPS, and got the
same three answers. Neither run exercised `High`, attested sensor liveness or isolated a real
endpoint; all consequential actions used protected mock providers.
