"""`Unknown(reason)`: a value the tool tried to learn and could not (story 126; #11).

Its own module so every record can use it without importing the device record. It is also
importable from `records.device`, where ticket #49 first defined it.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Unknown:
    """A value the tool tried to learn and could not. Never read it as "none".

    Attributes:
        reason: why, as fixed text, such as `show version not understood`.
    """

    reason: str
