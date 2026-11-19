"""The `scope` module: the Scope, the hard fence no login ever crosses.

Owns parsing and validating IPv4 Scope entries, exclusions and Seeds, and merging them into
a `ScopeRecord`. The record's `contains(ip)` is the single in-Scope check every later module
calls; it refuses 0.0.0.0/8, loopback, multicast, the reserved block (broadcast included) and
the network and broadcast addresses of Scope CIDRs. Calls no other module but `records`.
"""

from network_analyser.scope.parse import (
    Refusal,
    ScopeRefused,
    check_entry,
    check_seeds,
    parse,
    unmatched_exclusions,
)

__all__ = [
    "Refusal",
    "ScopeRefused",
    "check_entry",
    "check_seeds",
    "parse",
    "unmatched_exclusions",
]
