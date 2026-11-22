# `topology.json` (format version 3)

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

`format_version` is the first key: one integer, now `3`. It is bumped only when an older `render` would misread the file. An optional field may be added without a bump, because `render` ignores fields it does not know; `render` refuses a newer version. It was bumped to `3` on 2026-11-21 for the reason given under `devices[]` (#124), and to `2` on 2026-11-20 for the reason given under `findings[]`.

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
| `format_version` | `3` |
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
| `cisco_lookups` | optional (#104, read by #108): whether Cisco was asked during the Run and when |
| `analysis` | Analysis's advice and per-Check list (#94), or `null` before Analysis has run |

### `cisco_lookups` (#104, optional)

`ran` (true when Cisco was asked) and `when` (when the lookups ran, as fixed ISO 8601 text). Optional: a file with no key, or a Run with `--cisco-lookups off`, reads as "Cisco lookups did not run". Every surface reads it through `diagram.cisco_lookups(topology)`, so the shape changes in one place. Written by #104 (2026-11-21); a Run that did not ask Cisco records `{"ran": false, "when": null}`.

### `devices[]` (Visited Device)

`id`, `outcome` (`visited` / `partial`), `partial_reason`, `hostname`, `platform`, `model`, `software_version`, `serials[]`, `stack_members[]` (`number`, `serial`, `model`, `software_version`, `mode`), `management_ip`, `alias_ips[]` (learned aliases and interface addresses), `interfaces[]`, `vlan_database`, `vpc`, `hardware_series` (optional, #159), `router_operating_mode` (optional, #147), and the optional `advice` (#105).

`router_operating_mode` (#147): Cisco's `Router operating mode:` text, such as `Controller-Managed` on a Catalyst SD-WAN edge router, or `null` when `show version` prints no such line, as classic IOS and Catalyst 9000 switches do. Analysis reads it so an IOS XE SD-WAN device is never matched against IOS-XE Advisories (decision #78). It is an optional field: a file from before #147 lacks it, which reads as `null`, and no format-version bump was needed because no surface draws it.

`hardware_series` (#159): the one `Nexus<NNNN>` token `show version` named, such as `Nexus9000`, or `null` when it named none or more than one. Analysis reads it to settle the Nexus series for Advisory matching when the Device Role refused `show inventory | json`; it never supplies a chassis PID. It is an optional field, and no surface draws it, so no format-version bump was needed.

`stack_members[]` is the member table of `show version`: `software_version` and `mode` (such as `INSTALL` or `BUNDLE`) are read per member for the consistency Checks (#99), and are `{"unknown": reason}` when the table does not report them. They are optional fields; a file from before #99 has neither, and no format-version bump was needed because an older `render` drops them.

`advice` (#105, written from #124, read by #107, #108 and #109): the per-device Analysis advice: `outcome` (its Advisory outcome as text: "N Advisories match", "no known Critical/High Advisories for release X" or "could not check: reason"), `upgrade_target` (the release to move to, or the fixed text "no fix in Train T" / "no Critical/High Advisories" / "not available"), `latest_release` (newest overall; `latest_in_train` holds the newest in its Train), `latest_release_lifecycle` and `latest_in_train_lifecycle` (Cisco's lifecycle code beside each Latest Release, or `null` when there is none, #127), `train` (for example `17.12`, so the pages can say "no fix in Train T") and `not_cleared` (`0` when the target clears every Advisory, otherwise how many Advisories have no fix in the Train, #124). Optional, so a file from before #105, or a device Analysis did not advise, has none and the pages show "not available" rather than guessing (#89). The same record also stays in `analysis.advice[]` (`advisory_outcome` in its structured form). A version-3 file always records `not_cleared`; when a hand-edited or damaged file holds no usable count (absent, negative, fractional, true/false, text or null), `render` shows "count not recorded" beside the target rather than 0, because 0 would claim the target clears every Advisory (#146).


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
- `what_was_found` is fixed text plus names, keywords, type numbers and counts; `what_to_do` is the fix; `source` is `Cisco openVuln`, `config`, `device reports` or `tool policy, not a Cisco rule`. `what_to_do` is required on every Finding: for an Advisory it is the upgrade advice, and for an EoX Finding the replacement plan.
- `summary` is one line saying what is wrong, kept so the v1 pages still draw a Topology Finding. `kind` is v1's kind, `null` for an Analysis Finding. A file from before #93 has neither the new keys nor the new shape; its findings still draw.
- `cisco_detail` is one of two shapes, or `null`, told apart by its `kind` discriminator (`Advisory` or `EoX`), never by which fields happen to be present. An Advisory carries `kind`, `id`, `title`, `sir` (one of the four levels, equal to the Finding's `level`), `cvss`, `cves[]`, `published`, `updated`, `first_fixed` (`null` when the device's Train holds no fix Cisco names, or when Cisco's entry for the device's series was not resolved), `status` (the fixed `Affected release`), `fixed_line` (the fixed "version-only match" line, story 49), `hardware_family_not_confirmed` and `fix_unresolved` (true when the first fix is unknown rather than absent, so a page never prints "no fix in Train" for it). An EoX carries `kind` and `items[]` of `kind` (`hardware` or `software`, stories 74-75), `name`, `last_date_of_support`, `end_of_security_support`, `end_of_sw_maintenance`, `end_of_sale` and `replacement`. Dates are fixed ISO 8601 text.
- In the Findings tab an Advisory row is keyed by `cisco_detail.id`, not by the generic Check id, so one Advisory hitting 30 devices is one row; any other row is keyed by its Check id (stories 87, 89).
- `also_flagged_by_cisco` is `true` when Cisco's own insecure-configuration list flags the same thing.

### `analysis` (#94, 2026-11-20)

`advice[]` and `checks[]`, both optional. `findings` keeps every Finding, v1's and Analysis's together.

- `advice[]`: one per Visited Device, in device id order. `device`, `advisory_outcome`, `upgrade_target`, `latest_release_in_train`, `latest_release`, `latest_in_train_lifecycle`, `latest_release_lifecycle`, `train`, `not_cleared`, `upcoming_eox[]`. An Advisory outcome is `{"kind": "matches" | "none" | "could not check", "matched", "release", "reason"}`; `text` is built by the report from those fields. Upgrade Target and both Latest Releases are `not available` until Cisco's answers arrive (spec #92, Further Notes); `train` is the device's Train when worked out, and `not_cleared` is how many Advisories the target leaves open (#124). `upcoming_eox[]` reuses the EoX item shape (`name`, the four dates, `replacement`).
- `checks[]`: every shipped Check, in Check id order: `{"check": {...}, "ran": true | false, "reason": null | "...", "skipped": [...]}`. A Check is skipped only when a source it needs was unavailable. `skipped[]` is one `{"device", "reason"}` per Visited Device the Check could not run for (#102), such as a Device Role that refused its command or show output the Run did not collect; `ran` is false only when every Visited Device is in that list. A Check that does not apply to a device raises nothing and is not skipped.
- No Visited Device gets more than one advice record; Unvisited Devices get none (story 3).

`kind` is `conflicting evidence`, `Bundle member mismatch`, or a VLAN Mismatch (#61, 2026-11-19): `VLAN on one end only`, `differing native VLAN`, `trunk facing access`, `differing access VLANs`. A VLAN Mismatch's `items` is the Link or the Bundle, never a member Link. Its `evidence[].source` is `VLAN` for switchport and VLAN-database commands, or `CDP` when the native VLAN was advertised by an Unvisited Device.

**Format-version bump to 2 (2026-11-20, #93 follow-up).** The first Analysis Finding carries `kind: null`, and `cisco_detail` is now a discriminated union (`kind`). A pre-0.2.0 `render` reads a `kind: null` Finding as a v1 Finding and would misdraw it (its report code calls `item.kind.value`), so `format_version` is bumped to `2`. An older `render` refuses the newer file (story 113); a new `render` still reads version 1 files.

**Format-version bump to 3 (2026-11-21, #124).** Each Visited Device now carries its advice record, including `not_cleared`, and the Upgrade Target is each Advisory's first fix above the running release rather than the newest fix in the Train. A `render` from 0.2.0 would draw a partial target as if it cleared every Advisory, so `format_version` is bumped to `3`; that `render` refuses the new file. A new `render` still reads versions 1 and 2, showing "not available" where an old file holds no per-device advice.

### `skipped[]` and `unknown_interface_names[]`

`skipped[]`: `device`, `data`, `reason`. `data` is a `records/collected.py` field (`cdp`, `lldp`, `interfaces`, `vlans`, `port_channels`, `vpc`, `vrfs`, `arp`, `mac`, `routing_neighbours`, `static_routes`, `fhrp`, `stack_members`, and from #97/#98/#102 `inventory`, `snmp_users`, `ntp_associations`, `control_plane`, `ssh`, `insecure_configuration`, `guest_shell`) when that part was not collected. #61 also writes `vlan_mismatch` when a VLAN check on a Link or Bundle could not run; the reason names the gap and the link or bundle id. That is not a mismatch. A denied 0.2.0 command (`<command>: denied`) is what the Device Role out-of-date Check reads (#102).

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
- **#93 (Finding scale, 2026-11-20):** every Finding now carries `level`, `check` (stable id, name, type, `soft`), `what_was_found`, `what_to_do` and `source`, with optional `cisco_detail` and `also_flagged_by_cisco` (records in `records/topology.py`). v1's kinds are mapped in `topology/scale.py`: conflicting evidence and `VLAN on one end only` are Low (the latter `soft`); Bundle member mismatch, differing native VLAN, trunk facing access and differing access VLANs are Medium. New Analysis Findings carry no v1 `kind`, but they do carry a v1 `summary`. `format_version` is `2` (bumped by a follow-up; see under `findings[]`). A later Check ticket builds its own `Check(id, name, type)` and a `Finding` through the record, sorts with `Finding.order` (worst first, a soft Check last in its level) and writes it into `topology.json` as an optional field.
- **#104, #105:** write the optional `cisco_lookups` top-level record and each device's `advice` record described above. The pages read them through `diagram.cisco_lookups(topology)`, `diagram.device_advice(device)` and the Advisory pane, and show "Cisco lookups did not run" or "not available" when they are absent. Neither field needs a `format_version` bump.
- **#109 (2026-11-20):** the Map's count badge and Upgrade Target tag read Findings and each device's `advice` through `diagram.map_markers(topology)`, which uses `diagram.device_advice(device)` as the one reading of the advice fields. The badge counts the Findings naming the device and takes the colour of the worst level; a device with none has no badge. The tag is `↑ <release>` for an Upgrade Target, `no fix in Train` for `no fix in Train T` or a recorded null target, and `? could not check` for a could-not-check outcome. A device whose `advice` is absent, whose `upgrade_target` is unknown or `not available`, or whose outcome says there are no Critical/High Advisories, gets no tag: the tool never guesses. No field is added, and no device position changes.
- **#107 (Findings report, 2026-11-21):** `diagram.draw_findings_report(topology, redact, run_time=...)` draws `findings.html` from this file alone, one sheet per device worst first, with the Upgrade Target callout, the Advisories in one `<details>` and the other Findings in one table. `cli/findings_file.write_findings` reads the file and writes the page through the scanned writer at the end of every started Run and for `render`; the Run time comes from the Run folder's name. Every device field and Cisco field the page shows is already in this file; the page adds no key and needs no `format_version` bump.
- **#106 (Lifecycle Checks, 2026-11-21):** three `Lifecycle` Checks read Cisco's EoX and Software Suggestion answers: `lifecycle-hardware-eox` (one Finding per device at its worst level, with every affected `show inventory` item in `cisco_detail`), `lifecycle-software-eox` (one Finding per device for its release) and `lifecycle-suggested-release` (a Low Finding, or a Low "could not check" when Cisco returned nothing for the PID). A source marked unavailable skips its Check with the reason. Dates still in the future are never Findings: they ride `analysis.advice[].upcoming_eox`, each item carrying only its future dates and Cisco's replacement PID. No key is added and no `format_version` bump is needed.
- **#124 (Upgrade Target, 2026-11-21):** each Advisory's first fix is the lowest first-fixed release in the device's Train above the running release; the device's Upgrade Target is the highest of those, and `not_cleared` counts the Advisories with none. `topology/document.py` now writes each Visited Device's `advice` record (with `train` and `not_cleared`) beside `analysis.advice[]`. The Findings report callout adds "(does not clear N Advisories: no fix in Train T)", the Map tag adds "(no fix in Train)", the Advisory pane's device table adds "Not cleared", and the Run report's Visited Devices table shows the same advice. `format_version` is `3`; an older `render` refuses it.

- **#146 (map tag, not-cleared fail-open, v1/v2 callouts, render robustness, 2026-11-22):** a target that still leaves Advisories open is a `target-partial` tag in the warn colour, drawn as `↑ <release>` with `(no fix in Train)` on its own line, never truncated; a target whose recorded `not_cleared` is missing or invalid reads `count not recorded`, never a complete target. Advice the file does not hold (a v1/v2 file, or a device Analysis did not advise) renders as a neutral "not available" callout, not a red "could not check". The Advisory pane's "Not cleared" is `—` unless the target is a release or "no fix in Train T". A file nested too deeply to read is refused (exit 2), and the heading above names version 3. No field is added and `format_version` stays `3`.

- **#127 (Latest Release from the compatible list, 2026-11-21):** both Latest Release values now come from Software Suggestion's compatible list for the device's chassis PID, the highest overall and the highest in its own Train. Each value carries Cisco's lifecycle code in `latest_release_lifecycle` and `latest_in_train_lifecycle` (dropped when it does not pass the strict short pattern), and `running release is newer than Cisco's list` replaces a value the device already runs above. `findings.html` reads "Latest Release in Train: X (LC); overall: Y (LC)". The bare `latest_release` and `latest_in_train` fields keep their names and are still present, so the fields are optional additions: no `format_version` bump.
- **#153 (EoX could not check, 2026-11-22):** two more `Lifecycle` Checks, `lifecycle-hardware-eox-could-not-check` and `lifecycle-software-eox-could-not-check`, each raise one Low Finding per device when a hardware PID (refused by the safe pattern, with no Cisco record, or never asked) or a release (unreadable, outside the EoX family table, refused or with no Cisco record) has no EoX answer. They join the Advisory could-not-check Finding in the Run report's Needs attention list; a whole-source outage still skips all four EoX Checks, so it stays one line. A 4xx that is not an auth failure on one EoX or Software Suggestion batch is retried one value at a time, so only the values that still fail are unanswered. These are Findings and Check ids only: no `format_version` bump.
