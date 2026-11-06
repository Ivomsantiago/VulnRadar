"""Initial schema, frozen at revision 0001."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(160), primary_key=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss", sa.Float()),
        sa.Column("epss", sa.Float()),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("published", sa.String(60)),
        sa.Column("modified", sa.String()),
        sa.Column("triage", sa.String(50), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "aliases", sa.Column("id", sa.String(160), primary_key=True), sa.Column("vulnerability_id", sa.String(160), sa.ForeignKey("vulnerabilities.id"), nullable=False)
    )
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(240), primary_key=True),
        sa.Column("vulnerability_id", sa.String(160), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_table(
        "activity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("subject", sa.String(240), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "sources",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("checkpoint", sa.String()),
        sa.Column("last_run", sa.String()),
        sa.Column("error", sa.Text()),
        sa.Column("count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "watchlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ecosystem", sa.String(), nullable=False),
        sa.Column("package", sa.String(), nullable=False),
        sa.Column("version", sa.String()),
    )
    op.create_table(
        "projects", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(), nullable=False), sa.Column("path", sa.String(), nullable=False, unique=True)
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for table, columns in {
        "vulnerabilities": ["severity", "kev", "published", "triage"],
        "aliases": ["vulnerability_id"],
        "advisories": ["vulnerability_id", "source"],
        "activity": ["kind", "subject"],
        "watchlist": ["package"],
        "scans": ["project_id", "status"],
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    for table in ["scans", "projects", "watchlist", "sources", "activity", "advisories", "aliases", "vulnerabilities"]:
        op.drop_table(table)
