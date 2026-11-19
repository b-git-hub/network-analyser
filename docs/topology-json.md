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
| `findings` | things to look at (conflicts, Bundle member mismatches; later VLAN Mismatches) |
| `skipped` | data not collected, per device, so its checks were skipped (story 126) |
| `unknown_interface_names` | interface names the table did not know (story 127) |

### `devices[]` (Visited Device)

`id`, `outcome` (`visited` / `partial`), `partial_reason`, `hostname`, `platform`, `model`, `software_version`, `serials[]`, `stack_members[]` (`number`, `serial`, `model`), `management_ip`, `alias_ips[]` (learned aliases and interface addresses), `interfaces[]`, `vpc`.

`interfaces[]`: every interface, down ones included: `name`, `description`, `admin_up`, `line_up`, `speed`, `mode` (`access` / `trunk` / `routed` / `other`), `access_vlan`, `native_vlan`, `allowed_vlans`, `ip` (`vrf`, `addresses[]` primary first, `unnumbered`), `bundle` (port-channel short name), `stack_member`.

`vpc`: `domain`, `peer_link` (interface name), `keepalive` (`source`, `destination`, `vrf`), `port_channels[]` (`number`, `port_channel`).

### `unvisited[]` (Unvisited Device)

`id`, `reason` (one of the 13 fixed reasons, or unknown when the crawl recorded none), `label` (an advertised name, display only), `advertised_platform`, `advertised_ips[]`, `advertised_ipv6[]`, `chassis_id`, `reported_by[]` (`device`, `interface`, `evidence`).

Advertisements merge into one Unvisited Device only on a shared advertised address or LLDP chassis ID, never on a name. An advertisement carrying any address of a Visited Device (logged-into address, alias, interface address) is folded into it.

### `links[]`

`id`, `ends[2]` (`device`, `interface`; the interface is unknown when the far end did not advertise its port), `status` (`confirmed` when both ends report each other, else `one-sided`; #62 adds `inferred`), `evidence[]` (`device`, `command`, `source`), `role` (`vPC peer-link`, `vPC peer-keepalive` or null), `bundle` (Bundle id or null), `conflicts[]` (finding ids).

CDP and LLDP reports of one port pair, from either end, are one Link. When reports disagree (two Links claim one port), every claim is kept and each Link names the `conflicting evidence` finding.

### `segments[]` (Shared Segment)

`id`, `ports[]` (`device`, `interface`), `evidence[]`. A port that hears two or more devices connects to a Shared Segment, as does every port seen on it; overlapping views are one Segment.

### `bundles[]`

`id`, `sides[2]` (`ends[]` of `device` and `port_channel`, two ends on a vPC side; `vpc` number or null), `links[]` (member Link ids), `role` (`vPC peer-link` or null), `flagged[]` (member Link ids whose far end is not in a matching bundle). A `port_channel` of `null` means the members on that device are in no port-channel (flagged); unknown means it could not be told (never flagged).

### `findings[]`

`id`, `kind` (`conflicting evidence`, `Bundle member mismatch`; later tickets add theirs), `summary` (one line), `devices[]`, `items[]` (Link, Bundle, Segment ids), `evidence[]`.

### `skipped[]` and `unknown_interface_names[]`

`skipped[]`: `device`, `data` (the `records/collected.py` field: `cdp`, `lldp`, `interfaces`, `vlans`, `port_channels`, `vpc`, `vrfs`, `arp`, `mac`, `routing_neighbours`, `static_routes`, `fhrp`, `stack_members`), `reason`.

`unknown_interface_names[]`: `device`, `reported`.

## For the tickets that build on this

- **#59, #60 (collection):** fill `DeviceRecord.collected` with a `Collected`. Each part is a `Reading(commands, value, gaps)` or `Unknown(reason)`; never leave a part empty for "could not tell". Build every interface name with `records.interface_names.interface_name` (add new types to its table; a new entry changes no existing short name). Set `Interface.stack_member` on stacks and `Vrf.management` for `MANAGEMENT_VRFS`. Until then every Visited Device's data is unknown with the reason "not collected by this version of the tool".
- **#50 (crawl):** put a device's learned aliases in `DeviceRecord.aliases`. For each Neighbour address the crawl decides not to visit, hand `topology.build` a `DeviceRecord(ip, outcome=UNVISITED, unvisited_reason=...)`; it merges with the advertisements of that address. `cli/run_topology.Collector.add` must see every record (it is thread-safe), so `topology.json` after Ctrl+C holds what was found so far. Unify the crawl's neighbour record with `records.collected.Neighbour`.
- **#61, #62:** add their rules in `topology/build.py` after Bundles, their records to `records/topology.py`, and their finding kinds to `FindingKind`; new optional fields need no `format_version` bump. VLAN checks run on the Bundle (`Link.bundle`).
- **#63, #64, #65 (diagram, render):** read this file only; ignore unknown keys; refuse `format_version` above the one you know; treat any `{"unknown": ...}` as unknown, never absent. Escape every string. Write pages with `run_output.write_scanned_text`, scanning each value before HTML or XML escaping.
- **#66 (Run report):** list `skipped`, `unknown_interface_names` and `findings`; link with the ids above.
