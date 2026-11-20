"""Hand-written, synthetic replies for the NX-OS read-only commands of ticket #98.

The `| json` replies are shaped like Nexus JSON (`TABLE_<name>` / `ROW_<name>`, a lone row as
a bare object) and every text reply like the plain `show` form. Nothing here was captured
from a device: hostnames like `nx-a`, serials (`TEST...`), and RFC 5737 addresses only.

`ssh_key_reply` builds a public key blob here, at test time, so no real key is ever in the
repo: the blob is a synthetic RSA modulus of the requested size.
"""

import base64
import json
import struct
from typing import Final


def _json(data: object) -> str:
    return json.dumps(data, indent=2) + "\n"


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_rsa_key(bits: int) -> str:
    """Return a synthetic `ssh-rsa` public key whose modulus is `bits` bits long."""
    modulus = (1 << (bits - 1)) | 1
    blob = (
        _string(b"ssh-rsa") + _string(b"\x01\x00\x01") + _string(modulus.to_bytes(bits // 8, "big"))
    )
    return "ssh-rsa " + base64.b64encode(blob).decode("ascii")


def ssh_key_reply(bits: int = 2048) -> str:
    """Return a `show ssh key` reply holding one synthetic RSA key of `bits` bits."""
    return f"rsa Keys generated:Thu Jan  1 00:00:00 2026\n\n{ssh_rsa_key(bits)}\n"


INVENTORY: Final = _json(
    {
        "TABLE_inv": {
            "ROW_inv": [
                {
                    "name": "Chassis",
                    "desc": "Nexus9000 C9300v Chassis",
                    "productid": "N9K-C9300v",
                    "vendorid": "V01",
                    "serialnum": "TEST0000N01",
                },
                {
                    "name": "Slot 1",
                    "desc": "Supervisor Module",
                    "productid": "N9K-SUP-A",
                    "vendorid": "V01",
                    "serialnum": "TEST0000S01",
                },
                {
                    "name": "Slot 2",
                    "desc": "36x40G Ethernet Module",
                    "productid": "N9K-X9636C-RX",
                    "vendorid": "V01",
                    "serialnum": "TEST0000L01",
                },
                {
                    "name": "Power Supply 1",
                    "desc": "650W AC Power Supply",
                    "productid": "N9K-PAC-650W-B",
                    "vendorid": "V01",
                    "serialnum": "TEST0000P01",
                },
                {
                    "name": "Fan Tray 1",
                    "desc": "Fan Tray",
                    "productid": "N9K-C9300-FAN3",
                    "vendorid": "V01",
                    "serialnum": "TEST0000F01",
                },
                {
                    "name": "Ethernet1/1",
                    "desc": "10G SFP+ Transceiver",
                    "productid": "SFP-10G-SR",
                    "vendorid": "V01",
                    "serialnum": "TEST0000O01",
                },
            ]
        }
    }
)
"""One chassis, a supervisor, a line card, and a PSU, a fan and an optic to leave out."""

INVENTORY_TEXT: Final = (
    'NAME: "Chassis",  DESCR: "Nexus9000 C9300v Chassis"\n'
    "PID: N9K-C9300v,  VID: V01,  SN: TEST0000N01\n"
    "\n"
    'NAME: "Slot 1",  DESCR: "Supervisor Module"\n'
    "PID: N9K-SUP-A,  VID: V01,  SN: TEST0000S01\n"
    "\n"
    'NAME: "Power Supply 1",  DESCR: "650W AC Power Supply"\n'
    "PID: N9K-PAC-650W-B,  VID: V01,  SN: TEST0000P01\n"
)
"""The same command answered as plain text: a reply that ignored `| json`."""

NTP_PEER_STATUS: Final = _json(
    {
        "TABLE_peer_status": {
            "ROW_peer_status": [
                {
                    "peer": "*192.0.2.1",
                    "local": "192.0.2.11",
                    "st": "16",
                    "poll": "64",
                    "reach": "377",
                    "delay": "0.001",
                    "vrf": "default",
                },
                {
                    "peer": "192.0.2.2",
                    "local": "192.0.2.11",
                    "st": "16",
                    "poll": "64",
                    "reach": "0",
                    "delay": "0.000",
                    "vrf": "management",
                },
            ]
        }
    }
)

NTP_PEER_STATUS_TEXT: Final = (
    "Total peers : 2\n"
    "* - selected for sync, + - peer mode(active),\n"
    "# - peer mode(passive), = - polled in client mode\n"
    "    remote               local                 st   poll   reach delay   vrf\n"
    "*192.0.2.1             192.0.2.11             16   64     377   0.001   default\n"
    " 192.0.2.2             192.0.2.11             16   64     0     0.000   management\n"
)

NTP_PEER_STATUS_UNSYNCHRONISED: Final = _json(
    {
        "TABLE_peer_status": {
            "ROW_peer_status": [
                {
                    "peer": "192.0.2.1",
                    "local": "192.0.2.11",
                    "st": "16",
                    "poll": "64",
                    "reach": "0",
                    "delay": "0.000",
                    "vrf": "default",
                }
            ]
        }
    }
)

COPP_STATUS: Final = _json(
    {
        "policy-map": "copp-system-p-policy",
        "copp-status": "Policy copp-system-p-policy is applied",
    }
)

COPP_STATUS_TEXT: Final = "CoPP Status: Policy copp-system-p-policy is applied\n"

COPP_STATUS_NOT_APPLIED: Final = _json({"copp-status": "CoPP is not applied to the control plane"})

GUESTSHELL_ABSENT: Final = "guestshell is not installed\n"
GUESTSHELL_PRESENT: Final = "guestshell is enabled\n"

VIRTUAL_SERVICE_LIST_PRESENT: Final = (
    "Virtual Service List:\n"
    "\n"
    "Name                    Status\n"
    "-------------------------------------------------\n"
    "guestshell              Activated\n"
)

VIRTUAL_SERVICE_LIST_EMPTY: Final = (
    "Virtual Service List:\n\nName                    Status\n"
    "-------------------------------------------------\n"
)

SSH_KEY: Final = ssh_key_reply(2048)
SSH_KEY_WEAK: Final = ssh_key_reply(1024)

NEW_COMMANDS: Final = {
    "show inventory | json": INVENTORY,
    "show ntp peer-status | json": NTP_PEER_STATUS,
    "show copp status | json": COPP_STATUS,
    "show ssh key": SSH_KEY,
    "show guestshell": GUESTSHELL_ABSENT,
}
"""Every new command `nx-a` answers, and the healthy reply it gives."""
