# SPDX-License-Identifier: Apache-2.0
"""Match each covered host to its machine and build one envelope for it.

The verdict is Defender's own risk score and the confidence is fixed: what a score means is the
operator's mapping in ExecBound's bundle, so this code maps nothing and can never say `clean`.
A host with no single matching machine, or with no score, gets no envelope; its fact then
fails closed at the gateway, which is the only safe reading of silence.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from execbound_mde_producer.config import Config, CoveredHost
from execbound_mde_producer.defender import Machine

SCHEMA_VERSION = "execbound.security-signal.v1"
PRODUCER = "execbound-mde-producer"
CAPABILITY = "resource_compromise.v1"


@dataclass(frozen=True)
class Plan:
    envelopes: tuple[dict[str, Any], ...]
    uncovered: tuple[str, ...]


def envelope(
    config: Config, host: CoveredHost, machine: Machine, observed_at: datetime, version: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_event_id": f"{machine.machine_id}:{int(observed_at.timestamp())}",
        "producer": {"name": PRODUCER, "version": version},
        "capability": CAPABILITY,
        "verdict": machine.risk_score,
        "confidence": 1000,
        "subject": {
            "kind": "resource",
            "account_id": str(config.account_id),
            "provider": config.provider,
            "resource_type": config.resource_type,
            "provider_id": host.provider_id,
        },
        "observed_at": observed_at.isoformat(),
        "attributes": {"mde_machine_id": machine.machine_id},
    }


def plan(config: Config, machines: Sequence[Machine], observed_at: datetime, version: str) -> Plan:
    by_resource: dict[str, list[Machine]] = {}
    for item in machines:
        if item.azure_resource_id is not None:
            by_resource.setdefault(item.azure_resource_id.casefold(), []).append(item)
    built: list[dict[str, Any]] = []
    uncovered: list[str] = []
    for host in config.hosts:
        matched = by_resource.get(host.azure_resource_id.casefold(), [])
        if len(matched) != 1 or matched[0].risk_score is None:
            uncovered.append(host.provider_id)
            continue
        built.append(envelope(config, host, matched[0], observed_at, version))
    return Plan(tuple(built), tuple(uncovered))
