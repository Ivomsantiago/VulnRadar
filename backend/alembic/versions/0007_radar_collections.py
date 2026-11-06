"""Persist requested publication windows independently of incremental checkpoints."""

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "radar_collections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("basis", sa.String(20), nullable=False),
        sa.Column("enrich", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("progress", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_radar_collections_status", "radar_collections", ["status"])


def downgrade():
    op.drop_table("radar_collections")
