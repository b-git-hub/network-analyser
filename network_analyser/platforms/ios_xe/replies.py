"""What an IOS/IOS-XE reply says before it is parsed: denied, a feature that is off, or data (#59).

A Catalyst answers a command it will not run with an error in place of the output, on the
first line: a caret under the failed word, an `% Invalid input` (also for a command outside a
CLI view), `% Permission denied` or a TACACS+ refusal (`Command authorization failed.`). The
tool cannot tell a denial from a command the image does not have, so both are `denied`, the
same reason the NX-OS reader gives (`nxos.json_reply.DENIED`). A denied command leaves its
data unknown and is never fatal (spec #37; story 126).

A feature that is off answers with a `%` line too (`% BGP not active`); each collector says
what that means for its data. The reply text is never kept: these only classify it. The
patterns are provisional until lab check A3 records the real error texts.
"""

import re
from typing import Final

DENIED: Final = "denied"
"""The fixed reason for a denied command, after the command itself."""

_DENIAL: Final = re.compile(
    r"^\s*\^\s*$"
    r"|^\s*%\s*(?:Invalid input|Invalid command|Incomplete command|Ambiguous command"
    r"|Unrecognized command|Permission denied|Authorization failed)"
    r"|authori[sz]ation failed|permission denied",
    re.IGNORECASE,
)
_FEATURE_OFF: Final = re.compile(
    r"^\s*%.*\b(?:not (?:enabled|active|running|configured)|no router process)\b",
    re.IGNORECASE,
)
_ERROR: Final = re.compile(r"^\s*%")


def _first_line(text: str) -> str:
    return next((line for line in text.splitlines() if line.strip()), "")


def is_denied(text: str) -> bool:
    """Say whether a reply is the device refusing the command (or not having it)."""
    return _DENIAL.search(_first_line(text)) is not None


def is_feature_off(text: str) -> bool:
    """Say whether a reply is a `%` line saying the feature is not enabled or running."""
    return _FEATURE_OFF.search(_first_line(text)) is not None


def is_error(text: str) -> bool:
    """Say whether a reply opens with a `%` message rather than data."""
    return _ERROR.search(_first_line(text)) is not None
