"""Index affected package identities without discarding source ranges."""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "affected_packages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("advisory_id", sa.String(240), sa.ForeignKey("advisories.id"), nullable=False),
        sa.Column("ecosystem", sa.String(80), nullable=False),
        sa.Column("package", sa.String(300), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
    )
    for column in ("advisory_id", "ecosystem", "package"):
        op.create_index(f"ix_affected_packages_{column}", "affected_packages", [column])


def downgrade():
    op.drop_table("affected_packages")
