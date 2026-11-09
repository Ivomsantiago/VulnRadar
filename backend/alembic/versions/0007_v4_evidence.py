"""Add VEX provenance and feed indexes without changing historical records."""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("projects", sa.Column("internet_exposed", sa.Boolean(), nullable=True))
    op.create_index("ix_vuln_severity_published", "vulnerabilities", ["severity", "published", "id"])
    op.create_index("ix_vuln_kev_published", "vulnerabilities", ["kev", "published", "id"])
    op.create_table("vex_statements", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
                    sa.Column("package_version", sa.String(150), nullable=False),
                    sa.Column("format", sa.String(30), nullable=False),
                    sa.Column("artifact_sha256", sa.String(64), nullable=False),
                    sa.Column("justification", sa.String(100), nullable=False),
                    sa.Column("reason", sa.Text(), nullable=False), sa.Column("author", sa.String(80), nullable=False),
                    sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
                    sa.Column("applied", sa.Boolean(), nullable=False, server_default=sa.false()),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_vex_statements_finding_id", "vex_statements", ["finding_id"])


def downgrade():
    op.drop_column("projects", "internet_exposed")
    op.drop_table("vex_statements")
    op.drop_index("ix_vuln_kev_published", table_name="vulnerabilities")
    op.drop_index("ix_vuln_severity_published", table_name="vulnerabilities")
