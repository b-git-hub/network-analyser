# `topology.json` (format version 1)

Written 2026-11-19 for [#52](https://github.com/b-git-hub/network-analyser/issues/52) (spec [#37](https://github.com/b-git-hub/network-analyser/issues/37), "`topology.json` contract"; decided on [#11](https://github.com/b-git-hub/network-analyser/issues/11)).

Every started Run writes `topology.json` in its Run folder when it ends, including after Ctrl+C. It is the one plain-data seam between collecting and drawing: `render` (#63) and the diagram read only this file, and the later automated suite feeds synthetic device records into `topology.build` and reads what comes out.

## How it is made

```
DeviceRecord (records/device.py)            one per device tried, or chosen not to be tried
  .collected: Collected (records/collected.py)   filled by #59 (IOS/IOS-XE) and #60 (NX-OS)
        |
topology.build(records) -> Topology (records/topology.py)
topology.to_document(topology) -> plain JSON data
        |
cli/run_topology.py -> run_output.write_scanned_json -> topology.json
```

- `topology` imports only `records`: it never sees a file, a device or a secret.
- The cli writes the file with `run_output.write_scanned_json`, the shared scanned writer: every string, keys included, passes through the Run's secret scan *before* JSON escaping (a secret holding `"` or `\` would otherwise slip past a scan of the text), then the whole text again; temp file, flush, rename. A match is written as `[blocked]` (security test 5).
- It is plaintext. It holds no username (story 141), no password, no device output beyond parsed values, and nothing from the running config.

## Encoding rules

- Each record is a JSON object whose keys are the record's field names (`records/topology.py`, and the reused `records/collected.py` records).
- **Unknown** is `{"unknown": "<reason>"}`. It is never `null`, an empty list or a missing key. Empty (`[]`) means "there are none". `null` means "does not apply" (an access port's `allowed_vlans`, an IOS/IOS-XE device's `vpc`).
- Enums are their value: `"IOS/IOS-XE"`, `"NX-OS"`, `"visited"`, `"partial"`, `"confirmed"`, `"one-sided"`, `"CDP"`, `"LLDP"`, `"vPC peer-link"`.
- Addresses are strings: `"192.0.2.1"`, interface addresses `"192.0.2.1/24"`.
- VLAN sets (`allowed_vlans`) are lists of `[first, last]` ranges, lowest first: allowed all is `[[1, 4094]]`.
- Interface names are `{"short": "Gi1/0/1", "reported": "GigabitEthernet1/0/1", "known": true}`. `short` is canonical (the fixed table in `records/interface_names.py`); `known: false` means the table did not know it, so `short` is the name exactly as reported.
- Lists are in a fixed order (by id, or as each field says), so the same Run gives the same file.

## Format version

`format_version` is the first key: one integer, now `1`. It is bumped only when an older `render` would misread the file. An optional field may be added without a bump, because `render` ignores fields it does not know; `render` refuses a newer version.

## Stable ids

Every device and finding has an `id`, which `diagram.html#device=<id>`, `#finding=<id>` and the Run report share. Ids are worked out from what they name, never from the order things were found, so the same network gives the same ids:

| Item | Id |
|---|---|
| Visited Device | `dev-<first serial>`; `dev-ip-<management IP>` when no serial is known |
| Unvisited Device | `unv-<12 hex>` from its lowest advertised address, else its LLDP chassis ID, else the one report it is known from |
| Link, Shared Segment, Bundle, finding | `link-`, `seg-`, `bundle-`, `finding-` and 12 hex digits from its ends or subjects |
| L3 Adjacency (#62) | `adj-` and 12 hex digits from its kind, VRF, the two device ids and, for a shared subnet, the prefix |
| Subnet (#62) | `subnet-` and 12 hex digits from its VRF and prefix |

Ids hold only letters, digits, `.`, `-` and `_`. Items point at devices by id.

## Top level

| Key | Holds |
|---|---|
| `format_version` | `1` |
| `devices` | Visited Devices |
| `unvisited` | Unvisited Devices |
| `links` | physical Links |
| `segments` | Shared Segments |
| `bundles` | Bundles |
| `findings` | things to look at (conflicts, Bundle member mismatches, VLAN Mismatches) |
| `adjacencies` | L3 Adjacencies (#62). Empty when there are none |
| `subnets` | Subnets (#62): a prefix in one VRF shared by three or more devices. Empty when there are none |
| `skipped` | data not collected, per device, so its checks were skipped (story 126) |
| `unknown_interface_names` | interface names the table did not know (story 127) |
| `analysis` | Analysis's advice and per-Check list (#94), or `null` before Analysis has run |

### `devices[]` (Visited Device)

`id`, `outcome` (`visited` / `partial`), `partial_reason`, `hostname`, `platform`, `model`, `software_version`, `serials[]`, `stack_members[]` (`number`, `serial`, `model`), `management_ip`, `alias_ips[]` (learned aliases and interface addresses), `interfaces[]`, `vlan_database`, `vpc`.

`vlan_database` (#64): the VLANs in the device's VLAN database, active or not, as `[first, last]` ranges. Unknown when it was not collected or is incomplete. A trunk's effective VLANs are its `allowed_vlans` that are also here (#61's rule). A file written before #64 lacks the key, which reads as unknown.

`interfaces[]`: every interface, down ones included: `name`, `description`, `admin_up`, `line_up`, `speed`, `mode` (`access` / `trunk` / `routed` / `other`), `access_vlan`, `native_vlan`, `allowed_vlans`, `ip` (`vrf`, `addresses[]` primary first, `unnumbered`), `bundle` (port-channel short name), `stack_member`.

`vpc`: `domain`, `peer_link` (interface name), `keepalive` (`source`, `destination`, `vrf`), `port_channels[]` (`number`, `port_channel`).

### `unvisited[]` (Unvisited Device)

`id`, `reason` (one of the 13 fixed reasons, or unknown when the crawl recorded none), `label` (an advertised name, display only), `advertised_platform`, `advertised_ips[]`, `advertised_ipv6[]`, `chassis_id`, `reported_by[]` (`device`, `interface`, `evidence`).

Advertisements merge into one Unvisited Device only on a shared advertised address or LLDP chassis ID, never on a name. An advertisement carrying any address of a Visited Device (logged-into address, alias, interface address) is folded into it.

### `links[]`

`id`, `ends[2]` (`device`, `interface`; the interface is unknown when the far end did not advertise its port, and when an inferred Link's far port was not learned), `status` (`confirmed` when both ends report each other, else `one-sided`; #62 adds `inferred`), `evidence[]` (`device`, `command`, `source`), `role` (`vPC peer-link`, `vPC peer-keepalive` or null), `bundle` (Bundle id or null), `conflicts[]` (finding ids).

`source` is `CDP`, `LLDP`, `routing`, `MAC`, `ARP`, or `interface` (#62: interface addressing is not a routing-protocol report). An `inferred` Link was placed from ARP and the MAC table on one edge port. Its status is the confidence: there is no separate score.

CDP and LLDP reports of one port pair, from either end, are one Link. When reports disagree (two Links claim one port), every claim is kept and each Link names the `conflicting evidence` finding.

### `segments[]` (Shared Segment)

`id`, `ports[]` (`device`, `interface`), `evidence[]`. A port that hears two or more devices connects to a Shared Segment, as does every port seen on it; overlapping views are one Segment.

### `bundles[]`

`id`, `sides[2]` (`ends[]` of `device` and `port_channel`, two ends on a vPC side; `vpc` number or null), `links[]` (member Link ids), `role` (`vPC peer-link` or null), `flagged[]` (member Link ids whose far end is not in a matching bundle). A `port_channel` of `null` means the members on that device are in no port-channel (flagged); unknown means it could not be told (never flagged).

### `adjacencies[]` (L3 Adjacency, #62)

`id`, `ends[2]` (`device`, `interfaces[]` of interface names; empty when the protocol named none), `vrf`, `kind` (`shared subnet`, `OSPF`, `EIGRP`, `BGP`), `prefix` (the shared prefix, or null for a protocol neighbourship), `evidence[]`, `conflicts[]` (finding ids).

A prefix in one VRF on exactly two devices is one adjacency of kind `shared subnet`. The same prefix on three or more devices is a Subnet instead, not a set of pairs. A protocol neighbourship is its own adjacency even when the devices also share a prefix. /32s, FHRP virtual IPs, unnumbered interfaces and the management VRFs (`management`, `Mgmt-intf`) never create a shared-subnet adjacency.

### `subnets[]` (Subnet, #62)

`id`, `vrf`, `prefix`, `attachments[]` (`device`, `interface`, `address` with its mask), `evidence[]`, `conflicts[]`. One prefix, one VRF, each sharing device attached.

### `findings[]`

`id`, `devices[]`, `items[]` (Link, Bundle, Segment ids), `evidence[]`, `level`, `check`, `what_was_found`, `what_to_do`, `source`, `summary`, and the optional `kind`, `cisco_detail` and `also_flagged_by_cisco` (#93, 2026-11-20).

- `level` is `Critical`, `High`, `Medium` or `Low`. There is no Info level.
- `check` is the Check that raised it: `id` (stable in every Run), `name`, `type` (`Advisory`, `Configuration`, `Lifecycle`, `Consistency`, `Topology`) and `soft` (true for a Check shown fainter and listed last within its level, such as `VLAN on one end only`).
- `what_was_found` is fixed text plus names, keywords, type numbers and counts; `what_to_do` is the fix; `source` is `Cisco openVuln`, `config`, `device reports` or `tool policy, not a Cisco rule`.
- `summary` is one line saying what is wrong, kept so the v1 pages still draw a Topology Finding. `kind` is v1's kind, `null` for an Analysis Finding. A file from before #93 has neither the new keys nor the new shape; its findings still draw.
- `cisco_detail` is one of two shapes, or `null`: an Advisory's `id`, `title`, `sir`, `cvss`, `cves[]`, `published`, `updated`, `first_fixed` (`null` for no fix in the device's Train) and `hardware_family_not_confirmed`; or an EoX `items[]` of `name`, `last_date_of_support`, `end_of_security_support`, `end_of_sw_maintenance`, `end_of_sale` and `replacement`. Dates are fixed ISO 8601 text.
- `also_flagged_by_cisco` is `true` when Cisco's own insecure-configuration list flags the same thing.

### `analysis` (#94, 2026-11-20)

`advice[]` and `checks[]`, both optional. `findings` keeps every Finding, v1's and Analysis's together.

- `advice[]`: one per Visited Device, in device id order. `device`, `advisory_outcome`, `upgrade_target`, `latest_release_in_train`, `latest_release`, `upcoming_eox[]`. An Advisory outcome is `{"kind": "matches" | "none" | "could not check", "matched", "release", "reason"}`; `text` is built by the report from those fields. Upgrade Target and both Latest Releases are `not available` until Cisco's answers arrive (spec #92, Further Notes). `upcoming_eox[]` reuses the EoX item shape (`name`, the four dates, `replacement`).
- `checks[]`: every shipped Check, in Check id order: `{"check": {...}, "ran": true | false, "reason": null | "..."}`. A Check is skipped only when a source it needs was unavailable.
- No Visited Device gets more than one advice record; Unvisited Devices get none (story 3).

`kind` is `conflicting evidence`, `Bundle member mismatch`, or a VLAN Mismatch (#61, 2026-11-19): `VLAN on one end only`, `differing native VLAN`, `trunk facing access`, `differing access VLANs`. A VLAN Mismatch's `items` is the Link or the Bundle, never a member Link. Its `evidence[].source` is `VLAN` for switchport and VLAN-database commands, or `CDP` when the native VLAN was advertised by an Unvisited Device. `format_version` stays `1`: `kind` and `source` are plain strings an older `render` already keeps.

**No format-version bump for #93 (2026-11-20).** The new Finding fields are optional: an older `render` drops the keys it does not know and still draws the v1 `kind` and `summary` it reads, so it would not misread the file. A new `render` reads a file from before #93 with the new fields unknown. The bump rule in *Format version* is unchanged, and a newer file is still refused.

### `skipped[]` and `unknown_interface_names[]`

`skipped[]`: `device`, `data`, `reason`. `data` is a `records/collected.py` field (`cdp`, `lldp`, `interfaces`, `vlans`, `port_channels`, `vpc`, `vrfs`, `arp`, `mac`, `routing_neighbours`, `static_routes`, `fhrp`, `stack_members`) when that part was not collected. #61 also writes `vlan_mismatch` when a VLAN check on a Link or Bundle could not run; the reason names the gap and the link or bundle id. That is not a mismatch.

`unknown_interface_names[]`: `device`, `reported`.

## For the tickets that build on this

- **#59, #60 (collection):** fill `DeviceRecord.collected` with a `Collected`. Each part is a `Reading(commands, value, gaps)` or `Unknown(reason)`; never leave a part empty for "could not tell". Build every interface name with `records.interface_names.interface_name` (add new types to its table; a new entry changes no existing short name). Set `Interface.stack_member` on stacks and `Vrf.management` for `MANAGEMENT_VRFS`. Until then every Visited Device's data is unknown with the reason "not collected by this version of the tool".
- **#50 (crawl):** put a device's learned aliases in `DeviceRecord.aliases`. For each Neighbour address the crawl decides not to visit, hand `topology.build` a `DeviceRecord(ip, outcome=UNVISITED, unvisited_reason=...)`; it merges with the advertisements of that address. `cli/run_topology.Collector.add` must see every record (it is thread-safe), so `topology.json` after Ctrl+C holds what was found so far. Unify the crawl's neighbour record with `records.collected.Neighbour`.
- **#61 (VLAN Mismatches, 2026-11-19):** rules in `topology/vlan.py`, called from `topology/build.py` after Bundles. Effective VLANs are allowed ∩ present in the VLAN database (an inactive VLAN still counts as present). Four `FindingKind`s. Both ends must be Visited with the fields known, except native VLAN, where CDP's advertised native VLAN counts from an Unvisited Device. Missing data is a `skipped` row with `data` `vlan_mismatch`, never a finding. A Bundle is checked on its port-channel interfaces, not on member Links (`Link.bundle`). No `format_version` bump.
- **#62 (L3 Adjacency, Subnets and inference, 2026-11-19):** rules in `topology/l3.py` and `topology/inference.py`, called from `topology/build.py` after Bundles beside the VLAN checks. `adjacencies` and `subnets` are optional keys on format version 1. `build(records, scope=...)` records in-Scope routing neighbours and static next hops that CDP/LLDP never advertised as Unvisited Devices (`seen only in routing or ARP data (not crawled)`); it does not log into them. Inferred Links use `status: inferred` and, when several fall on one edge port, the existing Shared Segment. #64 draws them.
- **#63, #64, #65 (diagram, render):** read this file only; ignore unknown keys; refuse `format_version` above the one you know; treat any `{"unknown": ...}` as unknown, never absent. Escape every string. Write pages with `run_output.write_scanned_text`, scanning each value before HTML or XML escaping.
  - Built by #63 (2026-11-19): `diagram.read_topology(text)` is the loader. It keeps only the fields listed in its schema (`diagram/topology_file.py`), reads a known field the file lacks as unknown, and refuses a non-plain id. A later ticket that draws a new field adds it to that schema. `diagram.place(topology)` gives every device's position, shared by all views and `diagram.drawio`. `cli/diagram_file.write_diagram` draws the page from the Run folder's file, at Run end and for `render`.
  - Built by #65 (2026-11-19): `diagram.draw_drawio(topology, redact)` draws `diagram.drawio` from the same `TopologyFile` and `place` positions, and `write_diagram` writes it beside `diagram.html`. Its Routing page draws no routing lines while this file holds no routing adjacency (#62); when a later ticket adds that to the schema, draw it in `diagram/drawio.py` too. Calls: [spec-37-implementation-calls](wiki/spec-37-implementation-calls.md), items 6-14.
  - #62 (2026-11-19) added `adjacencies` and `subnets` to this file.
  - Built by #64 (2026-11-19): the diagram schema now reads `adjacencies`, `subnets`, `skipped` and devices' `vlan_database`; `place(...).subnets` positions Subnet nodes. `diagram.html` has the Map tab (Physical, Routing (L3), VLAN views, with Mismatch markers) and the Findings tab, which `#finding=<id>` opens. `diagram.drawio`'s Routing page draws Adjacencies and Subnets. Calls: [spec-37-implementation-calls](wiki/spec-37-implementation-calls.md), item 16.
- **#66 (Run report):** list `skipped`, `unknown_interface_names` and `findings`; link with the ids above.
- **#93 (Finding scale, 2026-11-20):** every Finding now carries `level`, `check` (stable id, name, type, `soft`), `what_was_found`, `what_to_do` and `source`, with optional `cisco_detail` and `also_flagged_by_cisco` (records in `records/topology.py`). v1's kinds are mapped in `topology/scale.py`: conflicting evidence and `VLAN on one end only` are Low (the latter `soft`); Bundle member mismatch, differing native VLAN, trunk facing access and differing access VLANs are Medium. New Analysis Findings carry no v1 `kind`, but they do carry a v1 `summary`. `format_version` stays `1` for the reason given under `findings[]`. A later Check ticket builds its own `Check(id, name, type)` and a `Finding` through the record, sorts with `Finding.order` (worst first, a soft Check last in its level) and writes it into `topology.json` as an optional field.
