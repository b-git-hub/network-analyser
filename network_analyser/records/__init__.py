"""The `records` leaf module: the plain-data records modules pass to each other (ADR 0003).

Every record is a `@dataclass(frozen=True, slots=True)` of plain values: str, int, bool,
None, tuples, frozensets, mappings, `ipaddress` objects, UTC-aware datetimes, enums and other
records. Never a `Secret`, a callable, a socket, a file or a live session, and never a
running config. Imports nothing from the package (CODING_STANDARDS.md, "Data").
"""
