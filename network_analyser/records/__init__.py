"""The `records` leaf module: the plain-data records modules pass to each other (ADR 0003).

Every record is a `@dataclass(frozen=True, slots=True)` of plain values: str, int, bool,
None, tuples, frozensets, mappings, `ipaddress` objects, UTC-aware datetimes, enums and other
records. Never a `Secret`, a callable, a socket, a file or a live session, and never a
running config. Imports nothing from the package (CODING_STANDARDS.md, "Data").
"""

from network_analyser.records.platform import CredentialSetView, Platform
from network_analyser.records.run_request import RunRequest, Source, Sourced
from network_analyser.records.scope import NEVER_TARGETS, AddressRange, Placement, ScopeRecord

__all__ = [
    "NEVER_TARGETS",
    "AddressRange",
    "CredentialSetView",
    "Placement",
    "Platform",
    "RunRequest",
    "ScopeRecord",
    "Source",
    "Sourced",
]
