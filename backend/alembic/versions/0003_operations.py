"""V2 operational inventory, findings and source history; additive migration."""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("stage", sa.String(40), nullable=False, server_default="queued"))
    op.add_column("scans", sa.Column("indexed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("watchlist", sa.Column("min_severity", sa.String(20), nullable=False, server_default="LOW"))
    op.add_column("watchlist", sa.Column("alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table(
        "inventory_components",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("ecosystem", sa.String(80), nullable=False),
        sa.Column("package", sa.String(300), nullable=False),
        sa.Column("version", sa.String(150), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("direct", sa.Boolean()),
        sa.Column("query_status", sa.String(30), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("vulnerability_id", sa.String(160), sa.ForeignKey("vulnerabilities.id")),
        sa.Column("package", sa.String(300)),
        sa.Column("ecosystem", sa.String(80)),
        sa.Column("version", sa.String(150)),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        sa.Column("rule_id", sa.String(300)),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("fixed_versions", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "kind", "fingerprint", name="uq_finding_identity"),
    )
    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_scan_finding"),
    )
    op.create_table("platform_settings", sa.Column("key", sa.String(80), primary_key=True), sa.Column("value", sa.JSON(), nullable=False))
    op.create_table(
        "sync_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("new_count", sa.Integer(), nullable=False),
        sa.Column("updated_count", sa.Integer(), nullable=False),
        sa.Column("processed_count", sa.Integer(), nullable=False),
        sa.Column("pages", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text()),
    )
    for table, columns in {
        "inventory_components": ["project_id", "scan_id", "ecosystem", "package"],
        "findings": ["project_id", "scan_id", "fingerprint", "kind", "vulnerability_id", "severity", "status"],
        "finding_observations": ["scan_id", "finding_id"],
        "sync_runs": ["source"],
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    for table in ("sync_runs", "platform_settings", "finding_observations", "findings", "inventory_components"):
        op.drop_table(table)
    for column in ("alerts_enabled", "min_severity"):
        op.drop_column("watchlist", column)
    for column in ("indexed", "stage"):
        op.drop_column("scans", column)
