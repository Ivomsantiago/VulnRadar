"""Persist webhook delivery outcomes without storing credentials."""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("activity_id", sa.Integer(), sa.ForeignKey("activity.id"), nullable=False, unique=True),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_attempt", sa.DateTime(timezone=True)),
        sa.Column("next_attempt", sa.DateTime(timezone=True)),
        sa.Column("error", sa.String(200)),
    )
    op.create_index("ix_notification_deliveries_status", "notification_deliveries", ["status"])


def downgrade():
    op.drop_table("notification_deliveries")
