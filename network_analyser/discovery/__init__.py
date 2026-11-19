"""The `discovery` module: Seeds, the optional Sweep and the CDP/LLDP crawl.

Owns the crawl queue, Neighbour address choice, Platform-hint gating, the worker pool,
de-duplication (host-key aliases and chassis serials), the Unvisited reasons and stopping.
`crawl(seeds, visit, ...)` returns every device found (#50) and stops on Ctrl+C through the
shared `RunStop` (#56); the Sweep (#55) comes later.
"""

from network_analyser.discovery.crawl import (
    ALL_SETS_RETIRED,
    MAX_ADDRESSES,
    STOPPED_BY_CTRL_C,
    TICK_S,
    IdentityRegister,
    Visit,
    crawl,
)

__all__ = [
    "ALL_SETS_RETIRED",
    "MAX_ADDRESSES",
    "STOPPED_BY_CTRL_C",
    "TICK_S",
    "IdentityRegister",
    "Visit",
    "crawl",
]
