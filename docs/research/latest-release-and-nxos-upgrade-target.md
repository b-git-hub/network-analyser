# Where the Latest Release and the NX-OS Upgrade Target come from

Research for [Where the Latest Release and the NX-OS Upgrade Target come from](https://github.com/b-git-hub/network-analyser/issues/89). It follows the live checks on [Get Cisco API access for openVuln, EoX and Software Suggestion](https://github.com/b-git-hub/network-analyser/issues/87) and the decision on [Which configuration, lifecycle and consistency Checks ship](https://github.com/b-git-hub/network-analyser/issues/81).

Findings dated **2026-11-20**. Each fact cites its source. Anything Cisco's own sources do not settle is marked **unverified**. No key was used and no account was made. The only live calls to Cisco's APIs were two unauthenticated requests that sent no device data (an OS type and the dummy PID `DUMMY-PID`). Both returned HTTP 403 `ERR_403_NOT_AUTHORIZED`, so `OS_version/OS_data` and `compatible/productId` need a key.

It builds on, and does not repeat, two earlier notes: `docs/research/cisco-advisory-data-sources.md` (branch `research/cisco-advisory-data-sources`) and `docs/research/cisco-eox-and-software-suggestion.md` (branch `research/cisco-eox-and-software-suggestion`).

Terms follow [GLOSSARY.md](../../GLOSSARY.md): **Advisory**, **Train**, **Upgrade Target**, **Latest Release**, **Suggested Release**. Two flags:

- **Upgrade Target** says "first-fixed releases ... within the device's own Train". Cisco's "First Fixed" is "the earliest release that fixes" an Advisory, with no Train in the definition (section 3.4). The glossary's Train limit is the project's own, not Cisco's.
- **Latest Release** says "for a device's model". Only Software Suggestion answers per model. openVuln's release list is per OS, or per NX-OS series (section 2.2).

## Sources

All fetched 2026-11-20.

| # | Source | URL | What was read |
|---|---|---|---|
| S1 | PSIRT openVuln guide "Retrieve Advisory based on Software Version" | https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/ (source: https://pubhub.devnetcloud.com/media/psirt/docs/guides/guide-retrieve-software.html) | Calls, `firstFixed` sample, NX-OS coverage |
| S2 | PSIRT openVuln OpenAPI 3.0.3 spec, as published on DevNet (v2.0.1) | https://developer.cisco.com/docs/psirt/ostypeostype/ and the JSON parts under https://pubhub.devnetcloud.com/media/psirt/docs/77abf0dd-caf5-31f5-9198-1d2476135141/ (`apis/OSType/{OSType}/get.json`, `apis/OS_version/OS_data/get.json`, `apis/platforms/get.json`, `models/Advisories.json`, `models/OSData.json`, `models/PlatformData.json`) | Parameters, response schemas |
| S3 | PSIRT openVuln "Pagination, sorting, filtering and rate limits" | https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits (source: `.../psirt/docs/guides/results.html`) | "Sorting is not supported" |
| S4 | PSIRT openVuln changelog | https://developer.cisco.com/docs/psirt/api-changelog (source: `.../psirt/docs/overview/changelog.html`) | Changes up to 2025-06-11 |
| S5 | Cisco's openVulnAPI repo, `swagger/openVulnAPIOAS_3_0_3.yaml` (last changed 2023-04-17) | https://github.com/CiscoPSIRT/openVulnAPI | Same schemas as S2 |
| S6 | Cisco's openVulnQuery client, commit `460c55c` (2025-06-28) | https://github.com/CiscoPSIRT/openVulnQuery | `advisory.py`, `constants.py`, `main.py`, `query_client.py`, README |
| S7 | openVulnQuery commit `7e819c5` by a Cisco PSIRT engineer (`@cisco.com` author), 2022-08-25 | https://github.com/CiscoPSIRT/openVulnQuery/commit/7e819c5dd99760c29ede1f37c7446dcb0139772c | Adds the `platforms` model and `platformAlias` |
| S8 | openVulnQuery issue 23, "get_by_nxos will return first_fixed with None" (2022-11-07, closed 2023-05-29), with a reply from that engineer (2022-11-09) | https://github.com/CiscoPSIRT/openVulnQuery/issues/23 | NX-OS reply shape, Cisco's explanation |
| S9 | openVulnAPI issue 70 (2019-08-21, closed 2020-02-19), with the PSIRT maintainer's NX-OS sample | https://github.com/CiscoPSIRT/openVulnAPI/issues/70 | NX-OS reply sample |
| S10 | openVulnAPI issue 83, "Different API response depending on platform" (2020-12-22, open) | https://github.com/CiscoPSIRT/openVulnAPI/issues/83 | NX-OS vs IOS-XE shapes (user report) |
| S11 | openVulnQuery issue 2, "NX-OS Plattform selection" (2020-12-28, closed 2022-10-05) | https://github.com/CiscoPSIRT/openVulnQuery/issues/2 | Why `platformAlias` exists |
| S12 | Software Suggestion API reference | https://developer.cisco.com/docs/support-apis/software-suggestion/ (source: https://pubhub.devnetcloud.com/media/support-apis/docs/software-suggestion.html) | Call descriptions, `SuggestionType`, samples |
| S13 | EoX API v5 reference | https://developer.cisco.com/docs/support-apis/eox/ | Record fields (via the earlier EoX note) |
| S14 | Cisco CSAF file `2026/cisco-sa-nxos-dsnmp-cnn39uh.json` | https://www.cisco.com/.well-known/csaf/2026/cisco-sa-nxos-dsnmp-cnn39uh.json | "Fixed Software" note, `product_status` |
| S15 | Cisco IOS and Cisco NX-OS Software Release Reference Guide (no date shown) | https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide | Release numbering |
| S16 | Cisco NX-OS Software Lifecycle Support Statement (updated 2026-10-09) | https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/nx-os-software/guide_c07-658595.html | `A.B(C)x`, F and M |
| S17 | Nexus 9000 release notes list | https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-release-notes-list.html | Release-note dates |
| S18 | Issue 87 resolution comment (2026-11-20) | https://github.com/b-git-hub/network-analyser/issues/87 | What the operator's key returned |

S6 to S11 are Cisco PSIRT's own GitHub repositories. S7 and the reply in S8 are by a Cisco PSIRT engineer; S9's sample is posted by the repo's PSIRT maintainer. S10 is a user's report, used only where Cisco's own sources agree.

## Summary

| Question | Answer |
|---|---|
| Latest Release from Software Suggestion | Only the two `compatible` calls are described as returning more than Cisco Suggested releases. The other four (`software`/`releases` by PID or mdfId) are described as "Cisco suggested software releases" only. Whether `compatible` with no `currentRelease` lists every release, including the newest, is **unverified**. |
| Latest Release from openVuln `OS_data` | Lists "software versions ... available in Cisco Software Checker", with `nos_type`, `nos_version` and (NX-OS only) `platform_name`. No date, no Train, no PID. It can give a newest release per Train and overall only by version order, per OS or per NX-OS series, not per model. It sends only the OS type. |
| Latest Release from EoX | No. EoX records have no release-list field. |
| "Newest" | Software Suggestion has `releaseDate`; `OS_data` has none. Cisco defines no order. Date order and version order disagree in Cisco's own release-note dates. |
| NX-OS first-fixed | Yes, inside `platforms`. Each entry is `{id, name, firstFixes, vulnerabilityState}`; `firstFixes` is a list of `{id, name}` and `name` is the release. Shown by Cisco's client and Cisco's samples, but absent from Cisco's OpenAPI spec. Whether the operator's 2026 replies fill it is **unverified**. |
| Within ADR 0007 | `OS_data` sends an OS type only. `OSType/nxos` without `platformAlias` sends OS type and release only. `compatible/productId` sends one PID. Sending `platformAlias` or `currentRelease` goes beyond ADR 0007's wording (section 4). |

## 1. Background: what issue 87 saw

- One key reached all three APIs. IOS-XE replies carried `firstFixed`; NX-OS 10.4(3) with `platformAlias=NEXUS9000` gave 18 Advisories with `platforms` and no `firstFixed`. ([S18](https://github.com/b-git-hub/network-analyser/issues/87))
- `releases/productIds` for three catalogue base PIDs gave 2 suggestions each, all `isSuggested Y`. ([S18](https://github.com/b-git-hub/network-analyser/issues/87))
- The script printed only the Advisory's field names, so it did not look inside `platforms`.

## 2. Latest Release

### 2.1 Software Suggestion v2

Cisco's own descriptions of the six calls ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/)):

| Call | Cisco's description | Sample `isSuggested` |
|---|---|---|
| `software/productIds/{ids}` | "Returns a list of Cisco suggested software releases and images for a list of product IDs." | all `Y` |
| `releases/productIds/{ids}` | "Returns a list of Cisco suggested software releases (without images) for a list of product IDs." | all `Y` |
| `software/mdfIds/{ids}` | "Returns a list of Cisco suggested software releases and images for a list of mdf IDs." | all `Y` |
| `releases/mdfIds/{ids}` | "Returns a list of Cisco suggested software releases (without images) for a list of mdf IDs." | all `Y` |
| `compatible/productId/{basePID}` | "Returns compatible and suggested software releases for a product given its product identifier (PID) and specific software attributes." | `N` |
| `compatible/mdfId/{mdfId}` | Same wording, by mdfId. | (sample not read) |

- So by Cisco's wording, the four `software`/`releases` calls list **Cisco Suggested releases only**. This matches what issue 87 saw. They cannot give the Latest Release.
- The `compatible` calls are the only ones described as returning "compatible" releases as well. Their sample has `"isSuggested": "N"`. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- Every filter on `compatible` is optional: `currentImage`, `currentRelease`, `supportedFeatures` (up to 10), `supportedHardware`, `pageIndex`. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- **Unverified:** whether `compatible` with no `currentRelease` lists every compatible release, including the newest one in each Train. Cisco's only sample has one record. The script checks this.
- **Unverified:** what `currentRelease` does to the list ("Current release version from which to filter the results" is all Cisco says).
- `compatible` takes **one** PID or mdfId per call, not 10. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- `isSuggested` is defined as "Indicates whether this release is Cisco Suggested", `Y` or `N`. `releaseTrain`: "All compatible release trains are included in the response." `releaseDate` example "17 Nov 2014". `releaseLifeCycle` is "Release lifecycle of the software", with no values listed; samples show `MD` and `ED`. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- Cisco's sample data is not internally consistent: `16.1.1` is dated 24 May 2016 and `16.1.2` 23 May 2016; the `compatible` sample dates `16.1.1` 02 Feb 2014; one `releaseTrain` is `"1.16"` for release `3.16.5S`. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/)) So the samples cannot show how real replies order or date releases.
- Empty or null fields are left out of the JSON. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))

### 2.2 openVuln `GET /OS_version/OS_data?OSType=…`

- Purpose, in Cisco's words: "To obtain the list of software versions for a network operating system available in Cisco Software Checker." One OS type per call. ([S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/))
- Only parameter: `OSType` (required). No paging parameter. ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/))
- Each item has three fields: `nos_type` (example `NXOS`), `nos_version` (example `7.0(3)F1(1)`), `platform_name` (example "Cisco Nexus 9000 Series Switches (Returned for - nxos)"). ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/), [S5](https://github.com/CiscoPSIRT/openVulnAPI))
- **No date, no Train, no PID, no "latest" flag.** `platform_name` is a series name, given for NX-OS only. So:
  - for IOS-XE, the list is per OS, not per model;
  - for NX-OS, it is per series at best.
- Cisco's client says: "Cisco reserves the right to remove End-of-Support releases from the Cisco Software Checker (subsequently reflected in this API)." ([S6](https://github.com/CiscoPSIRT/openVulnQuery) README)
- **Unverified:** the size of the list; whether NX-OS rows repeat per series; whether the newest releases appear as soon as Cisco posts them; whether NX-OS 10.x strings carry the `F`/`M` suffix; whether IOS-XE strings are padded. The script checks all but the timing.
- What it sends: the OS type only (`iosxe` or `nxos`). **No PID and no release string leaves the PC.**

### 2.3 EoX v5

- EoX records hold PIDs, dates, bulletin links and migration details. They have no field listing releases, so they cannot give a Latest Release. ([S13](https://developer.cisco.com/docs/support-apis/eox/); detail in `cisco-eox-and-software-suggestion.md`)

### 2.4 What "newest" means, and ordering pitfalls

- Cisco's docs define no "newest" or "latest" for either API. openVuln says: "Sorting is not supported in the Cisco PSIRT openVuln API. Client side code can be used to achieve this result." ([S3](https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits))
- Software Suggestion gives a `releaseDate` per release, so "newest" can mean newest by date. `OS_data` gives no date, so "newest" there can only mean highest by version order. ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/), [S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- **Date order and version order disagree.** Cisco's Nexus 9000 release-note dates: 9.3(16) on 04/Sep/2025, after 10.6(1)F on 13/Aug/2025; 9.3(13) on 18/Dec/2023, after 10.4(2)F on 14/Dec/2023. ([S17](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-release-notes-list.html)) These are release-note dates, not Software Suggestion `releaseDate` values.

Version-order pitfalls, each from a Cisco source:

| Pitfall | Example | Source |
|---|---|---|
| Text order is wrong | As text, `17.12.4` sorts before `17.9.5`, and `10.4(3)` before `9.3(13)`. Each part must be compared as a number. | IOS-XE parts are numbers that "increase by an increment of 1" ([S15](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide)) |
| Padding | `show version` prints `16.09.01`; Cisco's text says `16.9.1`. openVuln took both `17.12.04` and `17.12.4`. | [S15](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide), [S18](https://github.com/b-git-hub/network-analyser/issues/87) |
| Letter suffixes on IOS-XE | A "special release identifier ... increases by an increment of one lowercase, English alphabetical letter". Cisco's `firstFixed` sample holds `17.3.1w`, `17.3.2a`, `17.3.4b`, `17.3.5a`, `17.3.6`. How `17.3.2a` orders against `17.3.3` (a later build without the fix, or with it) is not stated. | [S15](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide), [S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/) |
| NX-OS 10.x `F`/`M` suffix | Releases are `A.B(C)x`, where x marks a Feature or Maintenance release: `10.5(1)F` ... `10.5(4)M`. Release-note titles carry the suffix (`10.4(3)F`); the lab's `show version` value `10.4(3)` was accepted by openVuln. C rises through the Train, so the suffix does not change order inside a Train. | [S16](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/nx-os-software/guide_c07-658595.html), [S17](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-release-notes-list.html), [S18](https://github.com/b-git-hub/network-analyser/issues/87) |
| NX-OS platform designators | Older NX-OS releases embed a platform part and a second number: `7.0(3)I7(9)`, `7.3(12)N1(1)`, `6.0(2)A8(4a)`. The Train is everything before the last bracket. | [S8](https://github.com/CiscoPSIRT/openVulnQuery/issues/23), [S15](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide) |
| Train of a release | IOS-XE: the first two numbers (`17.12`). NX-OS 10.x: `10.4`. Cisco gives no parsing rule for either. | **unverified** as a general rule |

## 3. NX-OS first-fixed releases

### 3.1 The `platforms` field holds them

Cisco's own client parses NX-OS (and every non-IOS) Advisory with a `platforms` list. Each item must have exactly four keys ([S6](https://github.com/CiscoPSIRT/openVulnQuery) `advisory.py`, `constants.py`; added in [S7](https://github.com/CiscoPSIRT/openVulnQuery/commit/7e819c5dd99760c29ede1f37c7446dcb0139772c)):

```
platforms: [ { id, name, firstFixes, vulnerabilityState }, ... ]
```

Cisco's samples fill in the shape:

- PSIRT maintainer's NX-OS sample, `nxos?version=8.3(1)`: platform `Cisco Nexus 7000 Series Switches` (id 265088), `firstFixes` with one item `8.4(1)` (id 265563), `vulnerabilityState` `vulnerable`; a second Advisory lists MDS 9000 and Nexus 7000, each with first fix `8.3(2)`. ([S9](https://github.com/CiscoPSIRT/openVulnAPI/issues/70))
- User's sample, confirmed by Cisco's reply: two platforms, `'id': '265090'`, `'name': 'Cisco Nexus 5000 Series Switches'`, `'vulnerabilityState': 'vulnerable'`, `'firstFixes': [{'id': '289274', 'name': '7.3(12)N1(1)'}]`. Ids are quoted strings. ([S8](https://github.com/CiscoPSIRT/openVulnQuery/issues/23))
- Cisco's engineer explains: "Cisco IOS and Cisco IOS XE doesn't have the concept of platform, it is a single product." For NX-OS, ACI and ASA the first fix is given per platform rather than per OS. His loop reads `platform.name`, `platform.firstFixes` and `fix['name']`, and with `platformAlias` `NEXUS9000` prints lines such as `Cisco Nexus 9000 Series Switches:9.3(10)`. ([S8](https://github.com/CiscoPSIRT/openVulnQuery/issues/23))

So the shape is:

```
"platforms": [
  { "id": "<number as text>",
    "name": "Cisco Nexus 9000 Series Switches",
    "firstFixes": [ { "id": "<number as text>", "name": "<release, e.g. 9.3(10)>" } ],
    "vulnerabilityState": "vulnerable" } ]
```

- The first-fixed release is `platforms[].firstFixes[].name`. There is no `firstFixed` on NX-OS Advisories. ([S8](https://github.com/CiscoPSIRT/openVulnQuery/issues/23), [S10](https://github.com/CiscoPSIRT/openVulnAPI/issues/83))
- **Neither `firstFixed` nor `platforms` is in Cisco's published OpenAPI spec.** The `Advisories` schema lists only `advisoryId` to `summary`, for every OS. ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/), [S5](https://github.com/CiscoPSIRT/openVulnAPI)) The spec is incomplete for version queries; the field shapes come from Cisco's client and samples only.
- Cisco's client (1.34) crashes on NX-OS replies, reported 2025-03-17 and still open ([openVulnAPI issue 97](https://github.com/CiscoPSIRT/openVulnAPI/issues/97)). This shows `platforms` is still sent, but not its current inner shape.
- **Unverified:** whether the operator's 2026 replies fill `firstFixes`; whether any other `vulnerabilityState` value exists; whether one platform can list several `firstFixes` (all samples show one). The script checks these.

### 3.2 `platformAlias`

- Optional on `OSType/{OSType}`, "Used only for nxos, asa, ftd and fxos". ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/)) NX-OS values: `MDS9000`, `NEXUS1000V`, `NEXUS3000`, `NEXUS5000`, `NEXUS6000`, `NEXUS7000`, `NEXUS9000`. ([S6](https://github.com/CiscoPSIRT/openVulnQuery) `constants.py`)
- `GET /platforms?OSType=nxos` returns `platformAlias`, `id` and `name` per platform (example `MDS9000`, 265086, "Cisco MDS 9000 Multilayer Directors and Fabric Switches"). ([S2](https://developer.cisco.com/docs/psirt/ostypeostype/)) The `id` matches the platform `id` in S9's sample (265086 for MDS 9000).
- It exists because "many versions are identical across platforms but have different vulnerability attributes". ([S11](https://github.com/CiscoPSIRT/openVulnQuery/issues/2)) Without it, the reply covers every affected platform, each with its own `firstFixes`. ([S8](https://github.com/CiscoPSIRT/openVulnQuery/issues/23))
- So the tool can either send `platformAlias`, or leave it out and keep only the `platforms` entry whose `name` matches the device's series. The PID-to-series mapping is the tool's job; Cisco publishes none for this API (**unverified** that one exists).

### 3.3 Coverage

- NX-OS version queries cover only Advisories first published from July 2019 onward. ([S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/))

### 3.4 What "First Fixed" means

- Cisco: the Software Checker "identifies any Cisco security advisories that impact a specific software release and the earliest release that fixes the vulnerabilities that are described in each advisory ("First Fixed"). If applicable, the tool also returns the earliest release that fixes all the vulnerabilities described in all the advisories that the Software Checker identifies ("Combined First Fixed")." ([S14](https://www.cisco.com/.well-known/csaf/2026/cisco-sa-nxos-dsnmp-cnn39uh.json), "Fixed Software" note) The openVuln version calls "query the Cisco Software Checker". ([S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/))
- **No Train is in the definition.** Cisco's own sample queries IOS-XE `17.2.1` and gets `firstFixed` `17.3.1w`, `17.3.2a`, `17.3.6`, `17.3.4b`, `17.3.5a`: all in Train 17.3, none in 17.2. ([S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/)) Likewise `7.0(3)I7(8)` gives first fix `7.0(3)I7(9)` ([S10](https://github.com/CiscoPSIRT/openVulnAPI/issues/83)), and the query in S8 names fixes in both `7.0(3)I7` and `9.3`.
- **One Advisory can list several first fixes in one Train** (five in 17.3 above). Cisco does not say how to pick one for a device. Taking the highest would pick `17.3.6`. Whether `17.3.3`, `17.3.4` and `17.3.5` are fixed is not stated (**unverified**).
- "Combined First Fixed" (the Software Checker's own answer for "every Advisory at once") is **not** in the API spec or Cisco's client. Whether the reply carries it is **unverified**; the script prints the reply's top-level field names.

### 3.5 Other Cisco sources (context only)

- **CSAF:** the 2026 NX-OS file checked lists only `product_status.known_affected`, no fixed releases; its "Fixed Software" note points to the Software Checker. ([S14](https://www.cisco.com/.well-known/csaf/2026/cisco-sa-nxos-dsnmp-cnn39uh.json)) Same as the six files in the earlier note. CSAF cannot give first-fixed. It is also keyless and on `www.cisco.com`, which ADR 0007's fence does not allow.
- **Software Checker web page** (`sec.cloudapps.cisco.com`): a page for people, not an API, outside the fence. The openVuln version calls are its supported API. ([S1](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software/))
- **Advisory pages** carry fixed-release tables as prose, outside the fence.
- **EoX** has no first-fixed field. ([S13](https://developer.cisco.com/docs/support-apis/eox/))
- **Software Suggestion** has no Advisory data. ([S12](https://developer.cisco.com/docs/support-apis/software-suggestion/))

So among the keyed sources already granted, **only openVuln's `OSType/nxos` gives NX-OS first-fixed releases**, in `platforms[].firstFixes[]`.

## 4. What the tool would send

ADR 0007 allows only "distinct PIDs ... and distinct OS type + release strings", to `id.cisco.com` and `apix.cisco.com`. ([ADR 0007](../adr/0007-cisco-lookups-at-run-end-after-secrets-wiped.md))

| Need | Call | Sends | Within ADR 0007's wording? |
|---|---|---|---|
| NX-OS first fixes | `GET apix.cisco.com/security/advisories/v2/OSType/nxos?version=<release>` | OS type + release | Yes |
| ... narrowed to a series | same, plus `&platformAlias=NEXUS9000` | OS type + release + series alias | **No**: a series alias is neither a PID nor a release. It names less than a PID does. Issue 87 already sent it. |
| Latest Release, per OS or NX-OS series | `GET .../OS_version/OS_data?OSType=iosxe` (or `nxos`) | OS type only | Yes; sends less than the ADR allows |
| Latest Release, per model | `GET apix.cisco.com/software/suggestion/v2/suggestions/compatible/productId/<basePID>` | One base PID per call | Yes, but one call per distinct PID, not 10 (ADR 0007 assumed 10 per Suggestion call) |
| ... filtered from the device's release | same, plus `?currentRelease=<release>` | PID **paired** with a release | **No** as worded: ADR 0007 lists PIDs and releases as separate distinct sets; this ties a model to its release in one request |

All of these are on `apix.cisco.com`, with the token from `id.cisco.com`.

## 5. What this means for #81

Facts only. The decisions belong to a later grilling ticket.

- **Latest Release, "taken from the Software Suggestion reply"**, cannot come from `releases/productIds`, which #81 assumed: by Cisco's wording that call (and `software/productIds`, and both mdfId versions) list Cisco Suggested releases only. This means the Latest Release can't be shown as decided.
- The only Software Suggestion calls that may list non-suggested releases are `compatible/productId` and `compatible/mdfId`. Whether they list every release, so that "newest" can be found, is **unverified**. They take one PID per call.
- openVuln `OS_data` gives every release Cisco's Software Checker knows, with no date and no model. It can give "highest in Train" and "highest overall" by version order, per OS (IOS-XE) or per NX-OS series, not "for the device's model" as GLOSSARY.md defines the Latest Release.
- "Newest" needs a definition. Cisco's sources give two (release date, version order) and they disagree.
- **NX-OS Upgrade Target:** a source exists, `platforms[].firstFixes[].name` in the same NX-OS reply the tool already asks for. #81's "highest first-fixed release within the Train" can be computed for NX-OS if the reply fills `firstFixes` (**unverified** for 2026 replies). Without `platformAlias`, the tool must pick the device's series from `platforms[].name`.
- **Upgrade Target in general:** Cisco's First Fixed is "the earliest release that fixes", in any Train. Cisco's own IOS-XE sample has no first fix in the queried Train. #81 already covers this with "no fix in Train T", so that case is expected, not rare.
- One Advisory can list several first fixes in one Train, and Cisco does not say which one applies. "Highest" is a choice #81 made, not Cisco's rule.
- ADR 0007 says up to 10 PIDs per Suggestion call; `compatible` takes one. `platformAlias` and `currentRelease` would each send something ADR 0007's wording does not list.

## 6. Unverified points and the lab script

Script: `lab/check-cisco-release-sources.ps1` on this branch. PowerShell 5.1, StrictMode, prompts for the client ID and a hidden secret, no files written, `MaximumRedirection 0`, only `id.cisco.com` and `apix.cisco.com`. It prints status codes, Cisco error codes, counts, field names, yes/no answers and Cisco's public release strings. **Not run**: this cloud session has no PowerShell.

Run it with the lab's releases and public catalogue PIDs only, for example:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\check-cisco-release-sources.ps1 -IosXeRelease 17.12.4 -NxosRelease '10.4(3)' -ProductId C9300-24T
```

| # | Unverified point | Script covers it? |
|---|---|---|
| U1 | 2026 NX-OS replies still have `platforms[].{id, name, firstFixes, vulnerabilityState}`, and `firstFixes` items are `{id, name}` | Yes: field names and item type |
| U2 | `firstFixes` is filled, and how many entries one platform has | Yes: counts |
| U3 | Other `vulnerabilityState` values | Yes: distinct values |
| U4 | NX-OS first fixes in the queried Train vs other Trains | Yes: counts per Train |
| U5 | What leaving out `platformAlias` adds | Yes: runs both |
| U6 | Whether a "Combined First Fixed"-like field is in the reply | Yes: top-level field names |
| U7 | How many IOS-XE Advisories list several first fixes in one Train, or none in the device's Train | Yes: counts |
| U8 | `OS_data` size, fields, series rows, padding, `F`/`M` suffixes, whether the lab release is listed, highest releases | Yes |
| U9 | Whether `OS_data` lists a new release as soon as Cisco posts it | No: needs watching over time |
| U10 | Whether `compatible/productId` and `compatible/mdfId` with no `currentRelease` list non-suggested and newer releases, and how many pages | Yes: Y/N counts, N newer than newest Y by date and by version, pages |
| U11 | Whether `software/productIds` or `releases/mdfIds` ever list `N` | Yes |
| U12 | `releaseLifeCycle` values and their meaning | Values yes; meaning no (Cisco does not define them) |
| U13 | What `currentRelease` does | No: it pairs a PID with a release, which ADR 0007 does not list; left out on purpose |
| U14 | How a lettered rebuild (`17.3.2a`) orders against the next plain release (`17.3.3`) for fixes | No: not answerable from the API |
| U15 | A general rule for a release's Train | No: Cisco publishes none |
| U16 | A Cisco mapping from PID to NX-OS series or `platformAlias` | No |
