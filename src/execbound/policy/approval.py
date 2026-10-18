# SPDX-License-Identifier: AGPL-3.0-only
"""Internal approval evidence; no request schema accepts this value."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class VerifiedApproval:
    approval_id: UUID
    tenant_id: UUID
    principal_id: UUID
    bundle_id: UUID
    plan_hash: str
    obligation_ids: tuple[str, ...]
    expires_at: datetime
