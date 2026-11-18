"""The `scope` module: the Scope, the hard fence no login ever crosses.

Owns parsing and validating IPv4 Scope entries and exclusions, merging them, the
in-Scope check `contains(ip)`, and refusing reserved, loopback, broadcast and multicast
targets. Calls no other module.
"""
