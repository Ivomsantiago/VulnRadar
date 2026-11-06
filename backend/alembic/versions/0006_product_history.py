"""Add product monitoring and immutable finding history; preserve all existing data."""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "affected_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("advisory_id", sa.String(240), sa.ForeignKey("advisories.id"), nullable=False),
        sa.Column("vendor", sa.String(200), nullable=False),
        sa.Column("product", sa.String(200), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
    )
    for column in ("advisory_id", "vendor", "product"):
        op.create_index(f"ix_affected_products_{column}", "affected_products", [column])
    op.create_table(
        "product_watches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vendor", sa.String(200), nullable=False),
        sa.Column("product", sa.String(200), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_table(
        "finding_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    for column in ("finding_id", "project_id", "occurred_at"):
        op.create_index(f"ix_finding_states_{column}", "finding_states", [column])


def downgrade():
    op.drop_table("finding_states")
    op.drop_table("product_watches")
    op.drop_table("affected_products")
