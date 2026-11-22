"""Readers for the new NX-OS read-only commands (tickets #97, #98; spec #92 stories 60-66).

One reader per command, each taking the reply exactly as the device gave it and returning
the plain records of `records.collected` (`#97`'s contract, shared with IOS/IOS-XE): the
inventory PIDs, the NTP associations, the control-plane policy, the SSH host key's size in
bits, and whether the Guest Shell is present. No reply, and no line of one, is kept: only the
parsed values leave here, so a secret in this output cannot reach a record, the Audit log or
a report.

The `| json` keys, and the text forms, are provisional until the lab confirms them (lab
checklist section L). A reply is read as JSON when it is JSON, and otherwise through the plain
`show` text, because a device or release that ignores the pipe sends the text form instead. A
reply with no recognisable shape raises `NotUnderstood`, so that part is `Unknown` and never a
guess.
"""

import base64
import binascii
import re
from collections.abc import Iterator
from ipaddress import AddressValueError, IPv4Address
from typing import Final

from network_analyser.platforms.nxos.json_reply import (
    NotUnderstood,
    Refused,
    Row,
    label,
    read,
    required,
    rows,
    text,
)
from network_analyser.records.collected import (
    ControlPlanePolicy,
    InventoryItem,
    InventoryKind,
    NtpAssociation,
    SshSettings,
)
from network_analyser.records.unknown import Unknown

# -- Inventory -----------------------------------------------------------------------------

_PID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9./-]{0,39}")
_SERIAL: Final = re.compile(r"[A-Za-z0-9]{1,40}")
_NOT_WANTED: Final = re.compile(
    r"power supply|\bpsu\b|\bfans?\b|fan tray|transceiver|optics?|\bsfp\b|\bqsfp\b",
    re.IGNORECASE,
)
_STACK_MEMBER_NAME: Final = re.compile(r"stack[- ]member", re.IGNORECASE)
_SUPERVISOR_NAME: Final = re.compile(r"supervisor|sup module|management module", re.IGNORECASE)
_LINE_CARD_NAME: Final = re.compile(r"line ?card|\bmodule\b", re.IGNORECASE)
_SLOT_NAME: Final = re.compile(r"slot \d{1,2}\b", re.IGNORECASE)
_NAME_LINE: Final = re.compile(
    r'^NAME:\s*"(?P<name>[^"]*)",\s*DESCR:\s*"(?P<desc>[^"]*)"\s*$', re.MULTILINE
)
_PID_LINE: Final = re.compile(
    r"^PID:\s*(?P<pid>[^,\s]+),\s*VID:\s*(?P<vid>[^,]*),\s*SN:\s*(?P<serial>.*)$", re.MULTILINE
)


def inventory(reply: str) -> tuple[InventoryItem, ...]:
    """The chassis, stack-member, supervisor and line-card PIDs; optics, PSUs and fans left out."""
    try:
        data = read(reply)
    except NotUnderstood:
        return _inventory_text(reply)
    if isinstance(data, Refused):
        raise NotUnderstood
    found = rows(data, "inv")
    if not found:
        return _inventory_text(reply)
    items: list[InventoryItem] = []
    for row in found:
        item = _inventory_item(
            required(row, "name"),
            text(row, "desc") or text(row, "description") or "",
            text(row, "productid") or text(row, "product_id") or text(row, "pid"),
            text(row, "serialnum") or text(row, "serial") or text(row, "sn"),
        )
        if item is not None:
            items.append(item)
    return tuple(items)


def _inventory_text(reply: str) -> tuple[InventoryItem, ...]:
    """The plain `show inventory` form: a NAME/DESCR line, then its PID/VID/SN line."""
    names = list(_NAME_LINE.finditer(reply))
    pids = list(_PID_LINE.finditer(reply))
    if not names or len(names) != len(pids):
        raise NotUnderstood
    found = (
        _inventory_item(
            name.group("name"), name.group("desc"), pid.group("pid"), pid.group("serial")
        )
        for name, pid in zip(names, pids, strict=True)
    )
    return tuple(item for item in found if item is not None)


def _inventory_item(
    name: str, description: str, product_id: str | None, serial: str | None
) -> InventoryItem | None:
    """One entry; None when it is not a part Cisco should be asked about (story 14)."""
    shown_name = label(name)
    kind = _kind(shown_name, label(description))
    if kind is None:
        return None
    return InventoryItem(shown_name, kind, _pid(product_id), _serial(serial))


def _kind(name: str, description: str) -> InventoryKind | None:
    """Which EoX kind an inventory entry is; None for anything that must never be sent."""
    both = f"{name} {description}"
    if _NOT_WANTED.search(both):
        return None
    if _STACK_MEMBER_NAME.search(name):
        return InventoryKind.STACK_MEMBER
    if _SUPERVISOR_NAME.search(both):
        return InventoryKind.SUPERVISOR
    if _LINE_CARD_NAME.search(both) or _SLOT_NAME.match(name):
        return InventoryKind.LINE_CARD
    if name.casefold() == "chassis" or "chassis" in description.casefold():
        return InventoryKind.CHASSIS
    return None


def _pid(value: str | None) -> str | Unknown:
    found = "" if value is None else value.strip()
    return found if _PID.fullmatch(found) else Unknown("PID not reported by show inventory")


def _serial(value: str | None) -> str | Unknown:
    found = "" if value is None else value.strip()
    return found if _SERIAL.fullmatch(found) else Unknown("serial not reported by show inventory")


# -- NTP synchronisation ---------------------------------------------------------------------

_NTP_ROW: Final = re.compile(
    r"^\s*(?P<mark>[*+#=])?\s*(?P<peer>(?:\d{1,3}\.){3}\d{1,3})\s+\S+\s+(?P<stratum>\S+)"
)
_NTP_NO_PEERS: Final = re.compile(r"total peers\s*:\s*0\b|\bno peers\b", re.IGNORECASE)

_NTP_PEER: Final = ("peer", "remote", "sys_peer")
_NTP_STRATUM: Final = ("st", "stratum")
_NTP_MARKERS: Final = ("state", "status", "peer-status", "peer_status")
_NTP_DIRECT: Final = ("selected", "sync", "synchronised", "synchronized")


def ntp_associations(reply: str) -> tuple[NtpAssociation, ...]:
    """The NTP peers, and which one (the `*` one) the device is synchronised to.

    An empty reply means no peers, never "unknown", as on IOS/IOS-XE (#97).
    """
    if not reply.strip():
        return ()
    try:
        data = read(reply)
    except NotUnderstood:
        return _ntp_text(reply)
    if isinstance(data, Refused):
        raise NotUnderstood
    found = rows(data, "peer_status")
    if not found:
        return _ntp_text(reply)
    return tuple(_ntp_association(row) for row in found)


def _ntp_association(row: Row) -> NtpAssociation:
    peer_value = next((value for key in _NTP_PEER if (value := text(row, key)) is not None), None)
    if peer_value is None:
        raise NotUnderstood
    marked = peer_value.strip().startswith("*")
    selected = marked or any(_marked(text(row, key)) for key in (*_NTP_STRATUM, *_NTP_MARKERS))
    selected = selected or any(_true(text(row, key)) for key in _NTP_DIRECT)
    stratum = _stratum(
        next(
            (value for key in _NTP_STRATUM if (value := text(row, key)) is not None),
            None,
        )
    )
    return NtpAssociation(_peer(peer_value), stratum, selected)


def _ntp_text(reply: str) -> tuple[NtpAssociation, ...]:
    if _NTP_NO_PEERS.search(reply):
        return ()
    found: list[NtpAssociation] = []
    for line in reply.splitlines():
        row = _NTP_ROW.match(line)
        if row is None:
            continue
        found.append(
            NtpAssociation(
                _peer(row.group("peer")),
                _stratum(row.group("stratum")),
                row.group("mark") == "*",
            )
        )
    if not found:
        raise NotUnderstood
    return tuple(found)


def _marked(value: str | None) -> bool:
    return value is not None and value.strip().startswith("*")


def _true(value: str | None) -> bool:
    return value is not None and value.strip().casefold() in {"true", "yes", "1", "enabled"}


def _peer(value: str) -> IPv4Address:
    shown = value.strip().lstrip("*+").strip()
    try:
        return IPv4Address(shown)
    except AddressValueError:
        raise NotUnderstood from None


def _stratum(value: str | None) -> int | Unknown:
    shown = "" if value is None else value.strip().lstrip("*")
    if not shown.isdigit():
        return Unknown("stratum not reported by show ntp peer-status")
    return int(shown)


# -- CoPP ------------------------------------------------------------------------------------

_COPP_NAMES: Final = ("policy-map", "policy_map", "policy-map-name", "policy", "name")
_COPP_STATUS: Final = ("copp-status", "copp_status", "status")
_COPP_NAME_TEXT: Final = re.compile(r"\bcopp[\w.:-]*policy\b", re.IGNORECASE)
_COPP_NOT_APPLIED: Final = (
    "not applied",
    "is not applied",
    "disabled",
    "not enabled",
    "no policy",
    "unattached",
    "not configured",
)
_COPP_APPLIED: Final = ("applied", "attached", "enabled", "success")
_MAX_DEPTH: Final = 3
"""How deep a CoPP JSON reply is searched for a status or policy name."""


def control_plane(reply: str) -> ControlPlanePolicy:
    """The control-plane policy NX-OS reports; an empty tuple means none is applied."""
    try:
        data = read(reply)
    except NotUnderstood:
        return _control_plane_text(reply)
    if isinstance(data, Refused):
        raise NotUnderstood
    strings = list(_keyed_strings(data))
    statuses = " ".join(value.casefold() for key, value in strings if key in _COPP_STATUS)
    names = tuple(
        dict.fromkeys(value for key, value in strings if key in _COPP_NAMES and value.strip())
    )
    if any(phrase in statuses for phrase in _COPP_NOT_APPLIED):
        return ControlPlanePolicy(())
    applied = any(phrase in statuses for phrase in _COPP_APPLIED) or bool(names)
    if not applied:
        raise NotUnderstood
    if not names:
        raise NotUnderstood  # applied, but the policy has no name we can trust
    return ControlPlanePolicy(names)


def _control_plane_text(reply: str) -> ControlPlanePolicy:
    shown = reply.casefold()
    if any(phrase in shown for phrase in _COPP_NOT_APPLIED):
        return ControlPlanePolicy(())
    if not any(phrase in shown for phrase in _COPP_APPLIED):
        raise NotUnderstood
    names = tuple(dict.fromkeys(label(m.group(0)) for m in _COPP_NAME_TEXT.finditer(reply)))
    if not names:
        raise NotUnderstood
    return ControlPlanePolicy(names)


def _keyed_strings(value: object, depth: int = 0) -> Iterator[tuple[str, str]]:
    """Every key and string value in a JSON reply, a few levels deep."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                yield key.lower(), item
            else:
                yield from _keyed_strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _keyed_strings(item, depth + 1)


# -- SSH host key size -----------------------------------------------------------------------

_BIT_COUNT: Final = re.compile(
    r"\b(?:bitcount|bit count|bits|key size)\s*[:=]?\s*(?P<bits>\d{3,5})\b", re.IGNORECASE
)
_BIT_WORD: Final = re.compile(r"\b(?P<bits>\d{3,5})\s*(?:bit|bits)\b", re.IGNORECASE)
_RSA_KEY: Final = re.compile(r"\bssh-rsa\s+(?P<key>[A-Za-z0-9+/=]+)")
_KEY_SECTION: Final = re.compile(
    r"^\s*(?P<kind>rsa|dsa|ecdsa|ed25519)\s+keys\s+generated\b", re.IGNORECASE | re.MULTILINE
)
_OTHER_KEY: Final = re.compile(r"\b(?:ecdsa-sha2-\S+|ssh-ed25519|ssh-dss)\b", re.IGNORECASE)
_SANE_BITS: Final = (512, 16384)
_MAX_FIELD: Final = 1024
"""The largest field a public key blob may hold: enough for an 8192-bit modulus."""
_NO_SSH_STATE: Final = "not reported by show ssh key"


def ssh_settings(reply: str) -> SshSettings:
    """SSH's host key size, from the key or a printed bit count; the rest is `Unknown`.

    `show ssh key` prints the key and nothing about the SSH server's version, so `enabled`
    and `version` are `Unknown` here, never guessed from the key. Only the bit count leaves
    here: the key itself is never kept, and a key that is not RSA cannot decide the size, so
    it raises `NotUnderstood` rather than guessing.
    """
    return SshSettings(Unknown(_NO_SSH_STATE), Unknown(_NO_SSH_STATE), _bits(reply))


def _bits(reply: str) -> int:
    section = _rsa_section(reply)
    found = _BIT_COUNT.search(section) or _BIT_WORD.search(section)
    if found is not None:
        return _sane_bits(int(found.group("bits")))
    key = _RSA_KEY.search(section)
    if key is None:
        raise NotUnderstood
    return _sane_bits(_rsa_key_bits(key.group("key")))


def _rsa_section(reply: str) -> str:
    """The part of a `show ssh key` reply that describes the RSA key, never another type's.

    The reply prints one section per key type (`rsa Keys generated:`, `ecdsa Keys
    generated:`), each with its own bit count, so reading the first count would size an
    ECDSA-only device's key as "521 bits". A reply with no section headers is read whole,
    unless it holds another key type and no RSA key.
    """
    headers = list(_KEY_SECTION.finditer(reply))
    if not headers:
        if _OTHER_KEY.search(reply) is not None and _RSA_KEY.search(reply) is None:
            raise NotUnderstood
        return reply
    for index, header in enumerate(headers):
        if header.group("kind").lower() == "rsa":
            end = headers[index + 1].start() if index + 1 < len(headers) else len(reply)
            return reply[header.end() : end]
    raise NotUnderstood


def _sane_bits(bits: int) -> int:
    smallest, largest = _SANE_BITS
    if not smallest <= bits <= largest:
        raise NotUnderstood
    return bits


def _rsa_key_bits(encoded: str) -> int:
    """The modulus size of an `ssh-rsa` public key blob (RFC 4253 section 6.6)."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except binascii.Error, ValueError:
        raise NotUnderstood from None
    kind, index = _field(raw, 0)
    if kind != b"ssh-rsa":
        raise NotUnderstood
    _, index = _field(raw, index)  # the public exponent
    modulus, _ = _field(raw, index)
    if not modulus:
        raise NotUnderstood
    return int.from_bytes(modulus, "big").bit_length()


def _field(raw: bytes, index: int) -> tuple[bytes, int]:
    if index + 4 > len(raw):
        raise NotUnderstood
    length = int.from_bytes(raw[index : index + 4], "big")
    start = index + 4
    if length > _MAX_FIELD or start + length > len(raw):
        raise NotUnderstood
    return raw[start : start + length], start + length


# -- Guest Shell -----------------------------------------------------------------------------

_GUEST_SHELL_OFF: Final = (
    "not installed",
    "not enabled",
    "disabled",
    "inactive",
    "not present",
    "not running",
    "not activated",
    "deactivated",
    "uninstalled",
    "no guestshell",
    "no guest shell",
)
_GUEST_SHELL_ON: Final = re.compile(r"\b(?:enabled|activated|active|running|installed)\b")
"""Whole words only: `activated` is inside `deactivated`, which is off."""


def guest_shell(reply: str) -> bool:
    """Say whether the Guest Shell is present, from `show guestshell`."""
    lowered = reply.lower()
    if "guestshell" not in lowered and "guest shell" not in lowered:
        raise NotUnderstood
    if any(phrase in lowered for phrase in _GUEST_SHELL_OFF):
        return False
    if _GUEST_SHELL_ON.search(lowered) is not None:
        return True
    raise NotUnderstood


def guest_shell_from_service_list(reply: str) -> bool:
    """Say whether the Guest Shell is present, from `show virtual-service list`."""
    lowered = reply.lower()
    for line in lowered.splitlines():
        if "guestshell" not in line:
            continue
        return not any(
            phrase in line
            for phrase in (
                "inactive",
                "deactivated",
                "not installed",
                "uninstalled",
                "disabled",
                "down",
            )
        )
    if "name" in lowered and "status" in lowered:
        return False  # a real list, with no Guest Shell in it
    raise NotUnderstood
