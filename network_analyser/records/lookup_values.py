"""The one set of strict patterns for every value the tool may send Cisco (#95, #130; ADR 0007).

`analysis` checks a value against these before it builds a lookup question, and `advisories`
checks it again at the fence, so the two cannot disagree about what a PID or a release looks
like. It lives in `records`, the leaf every module may import, for the same reason
`safe_names` does. It also holds the one rule for the bracketed suffix NX-OS prints after a
release, so `platforms` and `analysis` read a release the same way (#155).

A value leaves the PC only if it matches its pattern exactly. The patterns describe what the
tool means to send, not everything a device or Cisco might print, so an odd value is refused
alone rather than smuggled into a URL. A refusal never echoes the value: the text could be
hostile.

How a licence-suffixed PID is sent (#130, #162): `ISR4451-X/K9` is what `show inventory`
prints for an ISR 4000, and the whole string is the PID Cisco knows, so it is kept as it is in
every record and put in a request path as it is, slash included. Cisco's gateway refuses the
slash percent-encoded (`%2F` or `%252F`, HTTP 400) and answers it raw. A PID may hold one
slash followed by a short suffix of letters, digits and hyphens, and nothing else, so that
slash cannot add `..` or any other change to a URL. No character is ever encoded, so a percent
sign in a value is refused, not decoded.
"""

import re
from typing import Final

# A Cisco PID: letters, digits and hyphens, at least three characters and at least one digit,
# with an optional licence suffix such as `/K9`. Lower-case letters are real (`C9300v`,
# `N9K-C9300v`). No `=`, which marks a spare, and nothing that can change a URL.
_PID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{2,63}(?:/[A-Za-z0-9-]{1,16})?")
_DIGIT: Final = re.compile(r"[0-9]")

# The bracketed text NX-OS prints after the release in `show version`: `[build 7.0(3)I7(8.18)]`,
# `[Feature Release]`, or both. It is dropped before the release is read or checked, never sent.
_BRACKETED_SUFFIX: Final = re.compile(r"(?:\s*\[[^\]]*\])+\s*$")

# A normalised release: `17.9.4a`, `26.1.2s1`, `15.2(7)E9`, `15.1(4)M12a`, `9.3(10)`,
# `10.6(3s)`, `7.0(3)I4(8b)`. It starts with a major and a minor number, then at most three
# parenthesised parts (a number, up to two letters) and two dotted parts (a number, up to two
# letters, up to two digits). It admits every shape `analysis.releases` names a family for.
_RELEASE: Final = re.compile(
    r"[0-9]{1,2}\.[0-9]{1,2}"
    r"(?:\([0-9]{1,3}[a-z]{0,2}\)[A-Za-z]{0,3}[0-9]{0,3}[a-z]{0,2}){0,3}"
    r"(?:\.[0-9]{1,3}[a-z]{0,2}[0-9]{0,2}){0,2}"
)

# The Nexus hardware family openVuln matches NX-OS on, such as `NEXUS9000`.
_PLATFORM_ALIAS: Final = re.compile(r"NEXUS[0-9]{4}[A-Z]?")


def strip_release_suffix(text: str) -> str:
    """Drop the bracketed suffix NX-OS prints after a release (#137, #155).

    `show version` prints one or more after the release: `[build 7.0(3)I7(8.18)]`,
    `[Feature Release]`, or both. `platforms` and `analysis` share this one rule, so a release
    is read the same whichever side normalises it. The bracketed text is dropped, never sent.
    """
    return _BRACKETED_SUFFIX.sub("", text)


def is_safe_pid(value: object) -> bool:
    """Say whether `value` is a PID shape that may be sent."""
    return (
        isinstance(value, str) and _PID.fullmatch(value) is not None and bool(_DIGIT.search(value))
    )


def is_safe_release(value: object) -> bool:
    """Say whether `value` is a normalised release shape that may be sent."""
    return isinstance(value, str) and _RELEASE.fullmatch(value) is not None


def is_safe_platform_alias(value: object) -> bool:
    """Say whether `value` is an openVuln `platformAlias` shape that may be sent."""
    return isinstance(value, str) and _PLATFORM_ALIAS.fullmatch(value) is not None
