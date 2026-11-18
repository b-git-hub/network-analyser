"""Loading the Trust Store for `run` and `trust-key`, refusing with fixed messages (#46, #49).

A missing `--known-hosts` file, or one that names the Trust Store itself (which the tool
writes, story 46), refuses the command with exit 2 before any device is contacted.
"""

from pathlib import Path

from network_analyser import run_output, trust_store
from network_analyser.cli.run_folder import RefusedError, console_text
from network_analyser.trust_store import TrustStore


def load_trust_store(
    data: run_output.DataFolder, *, strict: bool = False, known_hosts: str | None = None
) -> TrustStore:
    """Read the Trust Store, and the `--known-hosts` file if one is given.

    Raises:
        RefusedError: the `--known-hosts` file is missing or unreadable, or names the
            Trust Store itself, or the Trust Store cannot be read.
    """
    preload = None if known_hosts is None else Path(known_hosts)
    try:
        return trust_store.load(data.trust_store, strict=strict, known_hosts=preload)
    except trust_store.PreloadIsTrustStoreError as error:
        msg = (
            "--known-hosts names the Trust Store itself, which the tool writes. "
            "Give a copy kept elsewhere."
        )
        raise RefusedError(msg) from error
    except FileNotFoundError as error:
        msg = f"the --known-hosts file {console_text(known_hosts or '')} was not found."
        raise RefusedError(msg) from error
    except OSError as error:
        msg = "the Trust Store or the --known-hosts file could not be read."
        raise RefusedError(msg) from error
