"""Enforce the authenticated workspace on ORM reads and writes."""
from pathlib import Path
from sqlalchemy import event, inspect, text
from sqlalchemy.orm import Session, with_loader_criteria
from api.models import WorkspaceScoped, DBWorkspace
from api.settings import DATA_ROOT

@event.listens_for(Session, "do_orm_execute")
def scope_queries(state):
    workspace_id = state.session.info.get("workspace_id")
    if workspace_id is not None and not state.execution_options.get("identity_lookup"):
        state.statement = state.statement.options(with_loader_criteria(
            WorkspaceScoped, lambda row: row.workspace_id == workspace_id, include_aliases=True))

@event.listens_for(Session, "before_flush")
def scope_writes(session, context, instances):
    workspace_id = session.info.get("workspace_id")
    if workspace_id is None:
        return  # Operator scripts and initial identity lookup do not use an HTTP session.
    for row in session.new | session.dirty | session.deleted:
        if isinstance(row, WorkspaceScoped):
            if row in session.new and row.workspace_id is None:
                row.workspace_id = workspace_id
            if row.workspace_id != workspace_id:
                raise ValueError("Cross-workspace write rejected")

def storage_root(workspace_id):
    # Retain the original installation's files and corresponding keys in place.
    root = DATA_ROOT if workspace_id == 1 else DATA_ROOT / "workspaces" / str(int(workspace_id))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.resolve().is_relative_to(DATA_ROOT.resolve()):
        raise ValueError("Invalid workspace storage directory")
    return root

def initialize_database(engine, base):
    # Additive migration: every pre-workspace record belongs to the original customer.
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            # Serialize cold starts and additive migrations across function instances.
            connection.execute(text("SELECT pg_advisory_xact_lock(8372600)"))
        base.metadata.create_all(connection)
        tables = inspect(connection)
        for table in ["users", "rules", "audit_logs", "threat_alerts", "scan_runs", "file_checks"]:
            if "workspace_id" not in {column["name"] for column in tables.get_columns(table)}:
                connection.execute(text(f'ALTER TABLE {table} ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1'))
            connection.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{table}_workspace_id ON {table} (workspace_id)'))
        if "scan_allowed_hosts" not in {c["name"] for c in tables.get_columns("workspaces")}:
            connection.execute(text("ALTER TABLE workspaces ADD COLUMN scan_allowed_hosts VARCHAR NOT NULL DEFAULT ''"))
        if "email" not in {c["name"] for c in tables.get_columns("users")}:
            connection.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR"))
        inserted = connection.execute(text("INSERT INTO workspaces (id, slug, name, scan_allowed_hosts) SELECT 1, 'main', 'Main workspace', '' WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE id = 1)"))

        if connection.dialect.name == "postgresql" and inserted.rowcount:
            connection.execute(text("SELECT setval(pg_get_serial_sequence('workspaces', 'id'), (SELECT MAX(id) FROM workspaces), true)"))
