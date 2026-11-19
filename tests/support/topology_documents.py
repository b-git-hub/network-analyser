"""Hand-written synthetic `topology.json` documents for the diagram, with no device (#63).

The other half of the seam: a synthetic Topology in, diagrams out. Fields a test does not
care about are left out; the reader treats them as unknown. Every name and address is
synthetic (RFC 5737 addresses, hostnames like `sw-a`).
"""

import json
from typing import Any

from network_analyser import diagram


def name(short: str) -> dict[str, object]:
    return {"short": short, "reported": short, "known": True}


def device(ident: str, hostname: str, address: str = "192.0.2.1", **fields: object) -> Any:  # noqa: ANN401
    return {
        "id": ident,
        "outcome": "visited",
        "hostname": hostname,
        "platform": "IOS/IOS-XE",
        "model": "C9300-48P",
        "management_ip": address,
        "serials": ["SYN1"],
        "alias_ips": [],
        "interfaces": [],
        "vpc": None,
        **fields,
    }


def unvisited_device(ident: str, label: str, reason: str, *reporters: str) -> Any:  # noqa: ANN401
    return {
        "id": ident,
        "reason": reason,
        "label": label,
        "advertised_platform": "cisco AIR",
        "advertised_ips": ["198.51.100.7"],
        "advertised_ipv6": [],
        "chassis_id": None,
        "reported_by": [
            {
                "device": r,
                "interface": name("Gi1/0/9"),
                "evidence": {"device": r, "command": "show cdp neighbors detail", "source": "CDP"},
            }
            for r in reporters
        ],
    }


def link(  # noqa: PLR0913 (both ends, by name)
    ident: str,
    a: str,
    a_port: str,
    b: str,
    b_port: str | None,
    *,
    status: str = "confirmed",
    role: str | None = None,
    bundle: str | None = None,
) -> Any:  # noqa: ANN401
    far: object = name(b_port) if b_port is not None else {"unknown": "no port advertised"}
    return {
        "id": ident,
        "ends": [{"device": a, "interface": name(a_port)}, {"device": b, "interface": far}],
        "status": status,
        "evidence": [{"device": a, "command": "show cdp neighbors detail", "source": "CDP"}],
        "role": role,
        "bundle": bundle,
        "conflicts": [],
    }


def bundle(  # noqa: PLR0913 (both sides, by name)
    ident: str,
    side_a: list[tuple[str, str]],
    side_b: list[tuple[str, str]],
    links: list[str],
    *,
    role: str | None = None,
    vpc: int | None = None,
) -> Any:  # noqa: ANN401
    def side(ends: list[tuple[str, str]], number: int | None) -> object:
        return {"ends": [{"device": d, "port_channel": p} for d, p in ends], "vpc": number}

    return {
        "id": ident,
        "sides": [side(side_a, None), side(side_b, vpc if len(side_b) > 1 else None)],
        "links": links,
        "role": role,
        "flagged": [],
    }


def adjacency(  # noqa: PLR0913 (both ends, by name)
    ident: str,
    a: str,
    b: str,
    kind: str = "shared subnet",
    prefix: str | None = "192.0.2.8/30",
    *,
    vrf: str = "default",
    ports: tuple[str, str] = ("Gi1/0/1", "Gi1/0/1"),
) -> Any:  # noqa: ANN401
    return {
        "id": ident,
        "ends": [
            {"device": a, "interfaces": [name(ports[0])]},
            {"device": b, "interfaces": [name(ports[1])]},
        ],
        "vrf": vrf,
        "kind": kind,
        "prefix": prefix if kind == "shared subnet" else None,
        "evidence": [{"device": a, "command": "show ip interface", "source": "interface"}],
        "conflicts": [],
    }


def subnet(ident: str, prefix: str, *attached: tuple[str, str, str], vrf: str = "default") -> Any:  # noqa: ANN401
    return {
        "id": ident,
        "vrf": vrf,
        "prefix": prefix,
        "attachments": [
            {"device": d, "interface": name(port), "address": address}
            for d, port, address in attached
        ],
        "evidence": [],
        "conflicts": [],
    }


def document(  # noqa: PLR0913 (each part of the Topology, by name)
    devices: list[Any],
    links: list[Any] = [],  # noqa: B006 (never changed)
    *,
    unvisited: list[Any] = [],  # noqa: B006
    segments: list[Any] = [],  # noqa: B006
    bundles: list[Any] = [],  # noqa: B006
    findings: list[Any] = [],  # noqa: B006
    adjacencies: list[Any] | None = None,
    subnets: list[Any] | None = None,
    skipped: list[Any] = [],  # noqa: B006
) -> Any:  # noqa: ANN401
    """Return a document; without `adjacencies` and `subnets` it is one from before #62."""
    made: dict[str, Any] = {
        "format_version": 1,
        "devices": devices,
        "unvisited": unvisited,
        "links": links,
        "segments": segments,
        "bundles": bundles,
        "findings": findings,
        "skipped": skipped,
        "unknown_interface_names": [],
    }
    if adjacencies is not None:
        made["adjacencies"] = adjacencies
    if subnets is not None:
        made["subnets"] = subnets
    return made


def read(data: object) -> diagram.TopologyFile:
    return diagram.read_topology(json.dumps(data))
