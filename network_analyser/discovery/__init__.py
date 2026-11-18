"""The `discovery` module: Seeds, the optional Sweep and the CDP/LLDP crawl.

Owns the crawl queue, Neighbour address choice, the worker pool, de-duplication, the
Unvisited reasons and stopping. `run(Run request)` yields event records and collected
device records; it hands device records to `backup_store` and `topology`.
"""
