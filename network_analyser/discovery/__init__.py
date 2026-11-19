"""The `discovery` module: Seeds, the optional Sweep and the CDP/LLDP crawl.

Owns the crawl queue, Neighbour address choice, Platform-hint gating, the worker pool,
de-duplication (host-key aliases and chassis serials), the Unvisited reasons and stopping.
`crawl(seeds, visit, ...)` returns every device found (#50). `sweep` probes the Scope on
TCP 22 and names the extra Seeds a banner allows (#55). Ctrl+C stopping comes later (#56).
"""

from network_analyser.discovery.crawl import (
    MAX_ADDRESSES,
    IdentityRegister,
    Visit,
    crawl,
)
from network_analyser.discovery.sweep import combine_seeds, sweep

__all__ = [
    "MAX_ADDRESSES",
    "IdentityRegister",
    "Visit",
    "combine_seeds",
    "crawl",
    "sweep",
]
