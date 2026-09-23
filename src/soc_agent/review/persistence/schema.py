"""Reproducible schema v1. No automatic migrations or destructive initialization."""

SCHEMA_VERSION = 1

# Only these static identifiers may be interpolated into SQL.
PARENTS = {
    "decisions": None,
    "review_requests": "decisions",
    "reviews": "review_requests",
    "requests": "reviews",
    "authorizations": "requests",
    "applications": "authorizations",
}


def statements() -> tuple[str, ...]:
    result = [
        "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "store_id TEXT NOT NULL)",
        """CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0),
            fingerprint TEXT NOT NULL, payload TEXT NOT NULL)""",
    ]
    result.append("""CREATE TABLE snapshots (
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id), revision INTEGER NOT NULL,
        fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
        PRIMARY KEY(incident_id, revision))""")
    for table, parent in PARENTS.items():
        parent_column = "parent TEXT," if parent else ""
        parent_constraint = (
            f", FOREIGN KEY(parent, incident_id) REFERENCES {parent}(id, incident_id)"
            if parent
            else ""
        )
        unique = (
            ", UNIQUE(parent)" if table in ("reviews", "authorizations", "applications") else ""
        )
        usage = ""
        if table == "authorizations":
            usage = """, used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
                application_id TEXT UNIQUE REFERENCES applications(id)
                    DEFERRABLE INITIALLY DEFERRED,
                CHECK((used=0 AND application_id IS NULL) OR
                      (used=1 AND application_id IS NOT NULL))"""
        result.append(f"""CREATE TABLE {table} (
            id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            {parent_column} payload TEXT NOT NULL, digest TEXT NOT NULL{usage},
            UNIQUE(id, incident_id){parent_constraint}{unique})""")
    result.append("""CREATE TABLE audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL)""")
    return tuple(result)
