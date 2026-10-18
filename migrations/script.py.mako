# SPDX-License-Identifier: AGPL-3.0-only
"""${message}"""

from alembic import op
${imports if imports else ""}
revision = "${up_revision}"
down_revision = ${repr(down_revision).replace("'", '"')}
branch_labels = ${repr(branch_labels).replace("'", '"')}
depends_on = ${repr(depends_on).replace("'", '"')}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
