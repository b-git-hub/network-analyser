r"""The data folder permissions check, part of the first Run-start step (#69; #150; decided on #7).

Made before any prompt, by `run` and by `trust-key`: only the operator may read or change
`%LOCALAPPDATA%\NetworkAnalyser\`, which holds the Trust Store and the Cisco API key file.
"""

import sys

from network_analyser import run_output
from network_analyser.cli.run_folder import RefusedError


def check_trust_folder(
    data: run_output.DataFolder, *, facts: run_output.FolderFacts | None = None
) -> str | None:
    """Check who can reach the Trust Store folder; print and return any warning.

    The warning is returned for the Run report.

    Raises:
        RefusedError: accounts other than the operator, SYSTEM and Administrators can read or
            change it, or Windows would not say who can.
    """
    check = run_output.check_trust_folder(data, facts=facts)
    if check.refusal is not None:
        raise RefusedError(check.refusal)
    if check.warning is not None:
        print(check.warning, file=sys.stderr)
    return check.warning
