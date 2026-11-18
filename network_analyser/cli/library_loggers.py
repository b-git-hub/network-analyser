"""Keep the netmiko and paramiko loggers silent (spec #37, security test 5; decision #30).

Netmiko's DEBUG logger records everything read from a device, and with no handler at all
Python's last-resort handler prints WARNING and above to stderr. So each library logger is
capped at WARNING, stops propagating, and gets a single handler that drops everything. This
is the only file that touches `logging`: our own files never use it.
"""

import logging

LIBRARY_LOGGERS = ("netmiko", "paramiko")


def silence_library_loggers() -> None:
    """Make sure nothing the SSH libraries log reaches the console or any file."""
    for name in LIBRARY_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        logger.handlers = [logging.NullHandler()]
