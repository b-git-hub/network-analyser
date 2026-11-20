"""Strict patterns on every value `advisories` sends Cisco (#95; stories 12-13; ADR 0007).

A value leaves the PC only if it matches its pattern exactly. The patterns describe what the
tool means to send, not everything Cisco might print, so an odd device string is refused
rather than smuggled into a URL. A refusal never echoes the value: the text could be hostile.

`analysis` builds the lookup questions from these same checks (ticket #104); this module
checks them again at the fence, because a value that reaches here out of pattern is a bug or
an attack, and either way it must not be sent.
"""

import re
from typing import Final

# A Cisco PID: uppercase letters, digits and hyphens, such as `C9300-48P` or
# `N9K-C93180YC-FX`. No `=`, which marks a spare, and nothing that can change a URL.
PID: Final = re.compile(r"[A-Z0-9][A-Z0-9-]{1,31}")

# A normalised release: `17.9.4a`, `15.2(7)E9`, `9.3(10)`, `7.0(3)I7(9)`. It starts with a
# major and a minor number, then at most three parenthesised parts and two dotted parts.
RELEASE: Final = re.compile(
    r"[0-9]{1,2}\.[0-9]{1,2}"
    r"(?:\([0-9]{1,3}\)[A-Za-z]{0,3}[0-9]{0,3}){0,3}"
    r"(?:\.[0-9]{1,2}[A-Za-z]{0,2}){0,2}"
)

# The Nexus hardware family openVuln matches NX-OS on, such as `NEXUS9000`.
PLATFORM_ALIAS: Final = re.compile(r"NEXUS[0-9]{4}[A-Z]?")


def is_safe_pid(value: str) -> bool:
    """Say whether `value` may be sent as a PID."""
    return PID.fullmatch(value) is not None


def is_safe_release(value: str) -> bool:
    """Say whether `value` may be sent as a normalised release string."""
    return RELEASE.fullmatch(value) is not None


def is_safe_platform_alias(value: str) -> bool:
    """Say whether `value` may be sent as openVuln's `platformAlias`."""
    return PLATFORM_ALIAS.fullmatch(value) is not None
