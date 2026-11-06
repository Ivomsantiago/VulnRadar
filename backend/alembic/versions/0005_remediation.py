"""Add remediation responsibility and time limits without altering findings."""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    for column in (
        sa.Column("owner", sa.String(150)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("risk_expires_at", sa.DateTime(timezone=True)),
        sa.Column("remediation_plan", sa.Text()),
    ):
        op.add_column("findings", column)


def downgrade():
    for column in ("remediation_plan", "risk_expires_at", "due_at", "owner"):
        op.drop_column("findings", column)
