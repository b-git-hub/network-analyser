"""Hand-written, synthetic NX-OS `| json` replies for the collection tests (#60).

Shaped like Nexus JSON (`TABLE_<name>` / `ROW_<name>`, a lone row as a bare object, numbers
sometimes as text) so the readers have something to read. Nothing here was captured from a
device: made-up hostnames (`nx-a`, `nx-b`, `sw-c`), serials (`TEST...`), MACs from the
documentation range `00005e005300`-`00005e0053ff` (RFC 7042), and RFC 5737 addresses.

`nx-a` is one of a vPC pair: domain 10, peer-link Po1 (Eth1/1-2), keepalive over mgmt0 in
the `management` VRF to `nx-b`, and Po10 (Eth1/3) joined to vPC 10.
"""

import json
from typing import Final


def _json(data: object) -> str:
    return json.dumps(data, indent=2) + "\n"


FEATURES: Final = _json(
    {
        "TABLE_cfcFeatureCtrlTable": {
            "ROW_cfcFeatureCtrlTable": [
                {
                    "cfcFeatureCtrlName2": "bgp",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "eigrp",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "disabled",
                },
                {
                    "cfcFeatureCtrlName2": "hsrp_engine",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "lacp",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "lldp",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "ospf",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "ospf",
                    "cfcFeatureCtrlInstanceNum2": 2,
                    "cfcFeatureCtrlOpStatus2": "disabled",
                },
                {
                    "cfcFeatureCtrlName2": "vpc",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "enabled",
                },
                {
                    "cfcFeatureCtrlName2": "vrrp",
                    "cfcFeatureCtrlInstanceNum2": 1,
                    "cfcFeatureCtrlOpStatus2": "disabled",
                },
            ]
        }
    }
)
"""bgp, hsrp, lldp, ospf and vpc on; eigrp and vrrp off."""

INTERFACES: Final = _json(
    {
        "TABLE_interface": {
            "ROW_interface": [
                {
                    "interface": "mgmt0",
                    "state": "up",
                    "admin_state": "up",
                    "eth_speed": "1000 Mb/s",
                },
                {
                    "interface": "Ethernet1/1",
                    "state": "up",
                    "admin_state": "up",
                    "desc": "to nx-b Eth1/1",
                    "eth_speed": "10 Gb/s",
                    "eth_mode": "trunk",
                },
                {
                    "interface": "Ethernet1/2",
                    "state": "up",
                    "admin_state": "up",
                    "desc": "to nx-b Eth1/2",
                    "eth_speed": "10 Gb/s",
                    "eth_mode": "trunk",
                },
                {
                    "interface": "Ethernet1/3",
                    "state": "up",
                    "admin_state": "up",
                    "desc": "to sw-c",
                    "eth_speed": "10 Gb/s",
                    "eth_mode": "trunk",
                },
                {
                    "interface": "Ethernet1/4",
                    "state": "down",
                    "admin_state": "down",
                    "eth_speed": "auto-speed",
                    "eth_mode": "routed",
                },
                {
                    "interface": "Ethernet1/5",
                    "state": "down",
                    "admin_state": "up",
                    "eth_speed": "auto-speed",
                    "eth_mode": "access",
                },
                {
                    "interface": "port-channel1",
                    "state": "up",
                    "admin_state": "up",
                    "desc": "vPC peer-link",
                    "eth_speed": "10 Gb/s",
                    "eth_mode": "trunk",
                },
                {
                    "interface": "port-channel10",
                    "state": "up",
                    "admin_state": "up",
                    "eth_speed": "10 Gb/s",
                    "eth_mode": "trunk",
                },
                {"interface": "loopback0", "state": "up", "admin_state": "up"},
                {
                    "interface": "Vlan10",
                    "svi_line_proto": "up",
                    "svi_admin_state": "up",
                    "svi_desc": "users",
                },
            ]
        }
    }
)

SWITCHPORT: Final = _json(
    {
        "TABLE_interface": {
            "ROW_interface": [
                {
                    "interface": "Ethernet1/1",
                    "switchport": "Enabled",
                    "oper_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "1",
                    "trunk_vlans": "1-4094",
                },
                {
                    "interface": "Ethernet1/2",
                    "switchport": "Enabled",
                    "oper_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "1",
                    "trunk_vlans": "1-4094",
                },
                {
                    "interface": "Ethernet1/3",
                    "switchport": "Enabled",
                    "oper_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "10",
                    "trunk_vlans": "10,20,30-32",
                },
                {
                    "interface": "Ethernet1/5",
                    "switchport": "Enabled",
                    "oper_mode": "access",
                    "access_vlan": "20",
                    "native_vlan": "1",
                    "trunk_vlans": "1-4094",
                },
                {
                    "interface": "port-channel1",
                    "switchport": "Enabled",
                    "oper_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "1",
                    "trunk_vlans": "1-4094",
                },
                {
                    "interface": "port-channel10",
                    "switchport": "Enabled",
                    "oper_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "10",
                    "trunk_vlans": "10,20,30-32",
                },
            ]
        }
    }
)

IP_INTERFACES: Final = _json(
    {
        "TABLE_intf": [
            {
                "ROW_intf": [
                    {
                        "intf-name": "Vlan10",
                        "proto-state": "up",
                        "link-state": "up",
                        "admin-state": "up",
                        "prefix": "192.0.2.129",
                        "subnet": "192.0.2.128",
                        "masklen": 25,
                        "num-addr": 2,
                        "TABLE_secondary_address": {
                            "ROW_secondary_address": {
                                "prefix1": "203.0.113.1",
                                "subnet1": "203.0.113.0",
                                "masklen1": "24",
                            }
                        },
                    },
                    {
                        "intf-name": "loopback0",
                        "proto-state": "up",
                        "link-state": "up",
                        "admin-state": "up",
                        "prefix": "198.51.100.200",
                        "subnet": "198.51.100.200",
                        "masklen": "32",
                    },
                    {
                        "intf-name": "Ethernet1/4",
                        "proto-state": "down",
                        "link-state": "down",
                        "admin-state": "down",
                        "prefix": "198.51.100.1",
                        "subnet": "198.51.100.0",
                        "masklen": "30",
                    },
                ]
            },
            {
                "ROW_intf": {
                    "intf-name": "mgmt0",
                    "proto-state": "up",
                    "link-state": "up",
                    "admin-state": "up",
                    "prefix": "192.0.2.11",
                    "subnet": "192.0.2.0",
                    "masklen": "24",
                }
            },
        ],
        "TABLE_vrf": [
            {"ROW_vrf": {"vrf-name-out": "default"}},
            {"ROW_vrf": {"vrf-name-out": "management"}},
        ],
    }
)
"""Two VRFs: each `TABLE_vrf` row names the VRF of the `TABLE_intf` entry beside it."""

PORT_CHANNELS: Final = _json(
    {
        "TABLE_channel": {
            "ROW_channel": [
                {
                    "group": 1,
                    "port-channel": "port-channel1",
                    "layer": "S",
                    "status": "U",
                    "type": "Eth",
                    "prtcl": "LACP",
                    "TABLE_member": {
                        "ROW_member": [
                            {"port": "Ethernet1/1", "port-status": "P"},
                            {"port": "Ethernet1/2", "port-status": "D"},
                        ]
                    },
                },
                {
                    "group": "10",
                    "port-channel": "port-channel10",
                    "layer": "S",
                    "status": "U",
                    "type": "Eth",
                    "prtcl": "NONE",
                    "TABLE_member": {"ROW_member": {"port": "Ethernet1/3", "port-status": "P"}},
                },
            ]
        }
    }
)

VLANS: Final = _json(
    {
        "TABLE_vlanbriefxbrief": {
            "ROW_vlanbriefxbrief": [
                {
                    "vlanshowbr-vlanid": 1,
                    "vlanshowbr-vlanid-utf": 1,
                    "vlanshowbr-vlanname": "default",
                    "vlanshowbr-vlanstate": "active",
                    "vlanshowbr-shutstate": "noshutdown",
                },
                {
                    "vlanshowbr-vlanid": 10,
                    "vlanshowbr-vlanid-utf": 10,
                    "vlanshowbr-vlanname": "users",
                    "vlanshowbr-vlanstate": "active",
                    "vlanshowbr-shutstate": "noshutdown",
                },
                {
                    "vlanshowbr-vlanid": 20,
                    "vlanshowbr-vlanid-utf": 20,
                    "vlanshowbr-vlanname": "voice",
                    "vlanshowbr-vlanstate": "suspend",
                    "vlanshowbr-shutstate": "noshutdown",
                },
            ]
        }
    }
)

VRFS: Final = _json(
    {
        "TABLE_vrf": {
            "ROW_vrf": [
                {"vrf_name": "blue", "vrf_id": 3, "vrf_state": "Up", "vrf_reason": "--"},
                {"vrf_name": "default", "vrf_id": 1, "vrf_state": "Up", "vrf_reason": "--"},
                {"vrf_name": "management", "vrf_id": 2, "vrf_state": "Up", "vrf_reason": "--"},
            ]
        }
    }
)

CDP: Final = _json(
    {
        "TABLE_cdp_neighbor_detail_info": {
            "ROW_cdp_neighbor_detail_info": [
                {
                    "ifindex": "436207616",
                    "device_id": "nx-b(TEST0000N02)",
                    "numaddr": "1",
                    "v4addr": "192.0.2.12",
                    "platform_id": "N9K-C9300v",
                    "capability": ["router", "switch"],
                    "intf_id": "Ethernet1/1",
                    "port_id": "Ethernet1/1",
                    "ttl": "150",
                    "version": "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(8)",
                    "nativevlan": "1",
                    "num_mgmtaddr": "1",
                    "v4mgmtaddr": "192.0.2.12",
                },
                {
                    "ifindex": "436208128",
                    "device_id": "sw-c",
                    "numaddr": "2",
                    "v4addr": ["198.51.100.20", "192.0.2.30"],
                    "platform_id": "cisco C9300-48P",
                    "capability": ["router", "switch", "IGMP_cnd_filtering"],
                    "intf_id": "Ethernet1/3",
                    "port_id": "GigabitEthernet1/0/49",
                    "version": "Cisco IOS Software [Cupertino]\nTechnical Support: x",
                    "nativevlan": "10",
                    "num_mgmtaddr": "1",
                    "v4mgmtaddr": "192.0.2.30",
                },
            ]
        }
    }
)

LLDP: Final = _json(
    {
        "TABLE_nbor_detail": {
            "ROW_nbor_detail": {
                "chassis_type": "Mac Address",
                "chassis_id": "0000.5e00.5302",
                "port_type": "Interface Name",
                "port_id": "Gi1/0/49",
                "l_port_id": "Eth1/3",
                "port_desc": "to nx-a",
                "ttl": 120,
                "sys_name": "sw-c",
                "sys_desc": "Cisco IOS Software, Catalyst L3 Switch",
                "system_capability": "B, R",
                "enabled_capability": "B, R",
                "mgmt_addr_type": "IPV4",
                "mgmt_addr": "192.0.2.30",
                "mgmt_addr_ipv6_type": "IPV6",
                "mgmt_addr_ipv6": "2001:db8::30",
                "vlan_id": "10",
            }
        }
    }
)

VPC_BRIEF: Final = _json(
    {
        "vpc-domain-id": "10",
        "vpc-peer-status": "peer-ok",
        "vpc-peer-keepalive-status": "peer-alive",
        "vpc-role": "primary",
        "num-of-vpcs": 1,
        "TABLE_peerlink": {
            "ROW_peerlink": {
                "peer-link-id": "1",
                "peerlink-ifindex": "Po1",
                "peer-link-port-state": "1",
                "peer-up-vlan-bitset": "1,10,20",
            }
        },
        "TABLE_vpc": {
            "ROW_vpc": {
                "vpc-id": 10,
                "vpc-ifindex": "Po10",
                "vpc-port-state": "1",
                "consistency-status": "SUCCESS",
            }
        },
    }
)

VPC_KEEPALIVE: Final = _json(
    {
        "vpc-keepalive-status": "peer-alive",
        "vpc-keepalive-send-status": "Success",
        "vpc-keepalive-last-send-intf": "mgmt0",
        "vpc-keepalive-dest": "192.0.2.12",
        "vpc-keepalive-vrf": "management",
        "vpc-keepalive-udp-port": "3200",
    }
)
"""No source address: NX-OS shows only the destination, so the source is the device's own
address in the keepalive VRF on the destination's subnet."""

ARP: Final = _json(
    {
        "TABLE_vrf": {
            "ROW_vrf": [
                {
                    "vrf-name-out": "default",
                    "cnt-total": 2,
                    "TABLE_adj": {
                        "ROW_adj": [
                            {
                                "intf-out": "Vlan10",
                                "ip-addr-out": "192.0.2.140",
                                "time-stamp": "00:01:02",
                                "mac": "0000.5e00.5310",
                            },
                            {
                                "intf-out": "Vlan10",
                                "ip-addr-out": "192.0.2.141",
                                "time-stamp": "00:01:02",
                                "mac": "INCOMPLETE",
                            },
                        ]
                    },
                },
                {
                    "vrf-name-out": "management",
                    "cnt-total": 1,
                    "TABLE_adj": {
                        "ROW_adj": {
                            "intf-out": "mgmt0",
                            "ip-addr-out": "192.0.2.12",
                            "time-stamp": "00:00:09",
                            "mac": "0000.5e00.5312",
                        }
                    },
                },
            ]
        }
    }
)

MAC: Final = _json(
    {
        "TABLE_mac_address": {
            "ROW_mac_address": [
                {
                    "disp_mac_addr": "0000.5e00.5310",
                    "disp_type": "*",
                    "disp_vlan": "10",
                    "disp_is_static": "disabled",
                    "disp_age": "0",
                    "disp_is_secure": "disabled",
                    "disp_is_ntfy": "disabled",
                    "disp_port": "Ethernet1/3",
                },
                {
                    "disp_mac_addr": "0000.5e00.5320",
                    "disp_type": "*",
                    "disp_vlan": "20",
                    "disp_is_static": "enabled",
                    "disp_age": "-",
                    "disp_is_secure": "disabled",
                    "disp_is_ntfy": "disabled",
                    "disp_port": "port-channel10",
                },
                {
                    "disp_mac_addr": "0000.5e00.5301",
                    "disp_type": "G",
                    "disp_vlan": "-",
                    "disp_is_static": "enabled",
                    "disp_age": "-",
                    "disp_is_secure": "disabled",
                    "disp_is_ntfy": "disabled",
                    "disp_port": "sup-eth1(R)",
                },
            ]
        }
    }
)

OSPF: Final = _json(
    {
        "TABLE_ctx": {
            "ROW_ctx": [
                {
                    "ptag": "1",
                    "cname": "default",
                    "nbrcount": 1,
                    "TABLE_nbr": {
                        "ROW_nbr": {
                            "rid": "198.51.100.202",
                            "priority": 1,
                            "state": "FULL",
                            "drstate": "DR",
                            "up": "P1DT2H",
                            "addr": "192.0.2.130",
                            "intf": "Vlan10",
                        }
                    },
                },
                {"ptag": "1", "cname": "blue", "nbrcount": 0},
            ]
        }
    }
)

BGP: Final = _json(
    {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": "default",
                "vrf-router-id": "198.51.100.200",
                "vrf-local-as": 65010,
                "TABLE_af": {
                    "ROW_af": {
                        "af-id": 1,
                        "TABLE_saf": {
                            "ROW_saf": {
                                "safi": 1,
                                "af-name": "IPv4 Unicast",
                                "TABLE_neighbor": {
                                    "ROW_neighbor": [
                                        {
                                            "neighborid": "203.0.113.9",
                                            "neighborversion": 4,
                                            "neighboras": 65020,
                                            "state": "Established",
                                        },
                                        {
                                            "neighborid": "203.0.113.10",
                                            "neighborversion": 4,
                                            "neighboras": 65030,
                                            "state": "Idle",
                                        },
                                    ]
                                },
                            }
                        },
                    }
                },
            }
        }
    }
)

STATIC_ROUTES: Final = _json(
    {
        "TABLE_vrf": {
            "ROW_vrf": [
                {
                    "vrf-name-out": "default",
                    "TABLE_addrf": {
                        "ROW_addrf": {
                            "addrf": "ipv4",
                            "TABLE_prefix": {
                                "ROW_prefix": [
                                    {
                                        "ipprefix": "0.0.0.0/0",
                                        "ucast-nhops": 1,
                                        "attached": "false",
                                        "TABLE_path": {
                                            "ROW_path": {
                                                "ipnexthop": "192.0.2.254",
                                                "ifname": "Vlan10",
                                                "pref": 1,
                                                "metric": 0,
                                                "clientname": "static",
                                                "ubest": "true",
                                            }
                                        },
                                    },
                                    {
                                        "ipprefix": "203.0.113.128/25",
                                        "ucast-nhops": 1,
                                        "TABLE_path": {
                                            "ROW_path": {
                                                "ifname": "Null0",
                                                "pref": 1,
                                                "metric": 0,
                                                "clientname": "static",
                                                "ubest": "true",
                                            }
                                        },
                                    },
                                ]
                            },
                        }
                    },
                },
                {
                    "vrf-name-out": "management",
                    "TABLE_addrf": {
                        "ROW_addrf": {
                            "addrf": "ipv4",
                            "TABLE_prefix": {
                                "ROW_prefix": {
                                    "ipprefix": "198.51.100.0/24",
                                    "ucast-nhops": 1,
                                    "TABLE_path": {
                                        "ROW_path": {
                                            "ipnexthop": "192.0.2.1",
                                            "pref": 1,
                                            "metric": 0,
                                            "clientname": "static",
                                            "ubest": "true",
                                        }
                                    },
                                }
                            },
                        }
                    },
                },
            ]
        }
    }
)

HSRP: Final = _json(
    {
        "TABLE_grp_detail": {
            "ROW_grp_detail": [
                {
                    "sh_if_index": "Vlan10",
                    "sh_group_num": 10,
                    "sh_group_type": "v4",
                    "sh_group_version": "v2",
                    "sh_group_state": "Active",
                    "sh_prio": 110,
                    "sh_cfg_prio": 110,
                    "sh_preempt": "enabled",
                    "sh_active_router_addr": "local",
                    "sh_standby_router_addr": "192.0.2.130",
                    "sh_vip": "192.0.2.254",
                },
                {
                    "sh_if_index": "Vlan10",
                    "sh_group_num": 11,
                    "sh_group_type": "v6",
                    "sh_group_state": "Active",
                    "sh_vip_v6": "2001:db8::1",
                },
            ]
        }
    }
)

NXOS_JSON_REPLIES: Final = {
    "show feature | json": FEATURES,
    "show interface | json": INTERFACES,
    "show interface switchport | json": SWITCHPORT,
    "show ip interface vrf all | json": IP_INTERFACES,
    "show port-channel summary | json": PORT_CHANNELS,
    "show vlan brief | json": VLANS,
    "show vrf | json": VRFS,
    "show cdp neighbors detail | json": CDP,
    "show lldp neighbors detail | json": LLDP,
    "show vpc brief | json": VPC_BRIEF,
    "show vpc peer-keepalive | json": VPC_KEEPALIVE,
    "show ip arp vrf all | json": ARP,
    "show mac address-table | json": MAC,
    "show ip ospf neighbors vrf all | json": OSPF,
    "show ip bgp summary vrf all | json": BGP,
    "show ip route static vrf all | json": STATIC_ROUTES,
    "show hsrp brief | json": HSRP,
}
"""Every collection command `nx-a` answers. EIGRP and VRRP are off, so their commands are
never sent."""

DENIED: Final = "% Permission denied for the role\n"
INVALID: Final = "                        ^\n% Invalid command at '^' marker.\n"
