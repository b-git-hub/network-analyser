"""The strict patterns on every value `advisories` sends Cisco (#95; stories 12-13; ADR 0007).

The patterns themselves live in `records.lookup_values`, one set that `analysis` and this
module both read (#130), so a value `analysis` asks for is never one this module refuses.
`analysis` builds the lookup questions from the same checks (ticket #104); this module checks
them again at the fence, because a value that reaches here out of pattern is a bug or an
attack, and either way it must not be sent. Only that value is refused: the rest of the
lookup is still asked.
"""

from network_analyser.records.lookup_values import (
    is_safe_pid,
    is_safe_platform_alias,
    is_safe_release,
)

__all__ = ["is_safe_pid", "is_safe_platform_alias", "is_safe_release"]
