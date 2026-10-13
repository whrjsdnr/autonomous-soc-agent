"""Optional store-owned disposition check; it never grants or changes policy authority."""

from uuid import UUID


def mutation_guard(store: object, incident_id: UUID | None, code: str) -> None:
    boundary = getattr(store, "boundary", None)
    if boundary is not None:
        boundary.mutation(incident_id, code)
        return
    database = getattr(store, "database", None)
    guard = getattr(database, "guard_mutation", None)
    if guard is not None:
        guard(incident_id, code)
