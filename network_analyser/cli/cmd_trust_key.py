"""`network-analyser trust-key IP --fingerprint SHA256:...` (story 45; ADR 0002).

Accepts a device's host key after the operator checked it on the device console: the key is
read from the device and saved in the Trust Store only if its fingerprint is the one typed.
No password is ever sent. Like a Run, it holds the single-instance lock and checks that only
the operator can reach the Trust Store folder (#69) before anything else (#46 follow-ups).

Exit codes: 0 saved or already trusted; 1 not saved (a different key, revoked, or the device
could not be reached); 2 refused before any device was contacted.
"""

import argparse
import sys
from ipaddress import AddressValueError, IPv4Address
from typing import Final

from network_analyser import device_gateway
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.run_folder import (
    RefusedError,
    console_text,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)
from network_analyser.cli.trust_folder import check_trust_folder
from network_analyser.cli.trust_keys import load_trust_store
from network_analyser.trust_store import AcceptOutcome

_NOT_IPV4: Final = "the device must be given as one IPv4 address, such as 192.0.2.10."
_MESSAGES: Final = {
    AcceptOutcome.SAVED: "Saved: the key the device presents matches, and is now trusted.",
    AcceptOutcome.ALREADY_TRUSTED: "Already trusted: nothing was changed.",
    AcceptOutcome.FINGERPRINT_MISMATCH: (
        "Not saved: the device presents a different key. Check the fingerprint on the device "
        "console again; never accept a key you have not checked."
    ),
    AcceptOutcome.REVOKED: "Not saved: that key is marked @revoked in the Trust Store.",
}


def trust_key(args: argparse.Namespace) -> ExitCode:
    """Read the device's host key and save it if it matches `--fingerprint`."""
    try:
        ip = _address(args.ip)
        data = find_data_folder()
        with hold_instance_lock(data):
            check_trust_folder(data)  # #69: only the operator may reach the Trust Store
            trust = load_trust_store(data)
            result = device_gateway.trust_key(ip, args.fingerprint, trust=trust)
    except RefusedError as error:
        refuse(args.command, fixed_message(error))
        return ExitCode.REFUSED
    if result.failure == device_gateway.NOT_A_TARGET:
        refuse(args.command, f"{result.failure}. Nothing was contacted.")
        return ExitCode.REFUSED
    for fingerprint in result.presented:
        print(f"The device presents {console_text(fingerprint)}")
    if result.outcome is None:
        print(f"Not saved: {result.failure}.", file=sys.stderr)
        return ExitCode.NEEDS_ATTENTION
    print(_MESSAGES[result.outcome])
    if result.outcome in {AcceptOutcome.SAVED, AcceptOutcome.ALREADY_TRUSTED}:
        return ExitCode.CLEAN
    return ExitCode.NEEDS_ATTENTION


def _address(text: str) -> IPv4Address:
    try:
        return IPv4Address(text)
    except AddressValueError as error:
        raise RefusedError(_NOT_IPV4) from error
