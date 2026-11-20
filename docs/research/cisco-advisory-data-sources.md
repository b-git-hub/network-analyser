# Cisco Advisory and lifecycle data sources

Research for [Cisco Advisory and lifecycle data sources](https://github.com/b-git-hub/network-analyser/issues/75), a child of [Map: Network Analysis, the way to a build spec](https://github.com/b-git-hub/network-analyser/issues/74).

Findings dated **2026-11-20**. Every fact cites the page it came from. "Checked" means this session fetched the URL itself on 2026-11-20 without credentials. Anything marked **unverified** could not be confirmed from a Cisco or NIST source. No account was created and no credentials were used, so nothing behind a login was read.

Terms follow [GLOSSARY.md](../../GLOSSARY.md): an **Advisory** is a Cisco Security Advisory, **Analysis** is the work that matches a **Visited Device**'s software against Advisories, and a **Platform** is IOS/IOS-XE or NX-OS.

## Summary

| Source | Key needed? | Who can get one | Gives | Hosts |
|---|---|---|---|---|
| CSAF 2.0 files (`/.well-known/csaf/`) | **No** | Anyone | Every affected version for each Advisory, CVSS v3.1, CVE, bug ids, feature conditions as prose. No SIR, no first-fixed. | `www.cisco.com` (and `cscrdr.cloudapps.cisco.com` once, for the PGP key) |
| PSIRT openVuln API v2 | **Yes**: OAuth2 client credentials | Any Cisco.com account (no contract mentioned) | Advisories for an OS + version, with SIR, CVSS base score, CVEs, first-fixed, SMUs | `id.cisco.com`, `apix.cisco.com` |
| Cisco Software Checker (web) | No | Anyone | Same data as the openVuln version endpoints, for people | `sec.cloudapps.cisco.com` |
| EoX API v5 (Support APIs) | **Yes**: OAuth2 client credentials | **Only** SNTC customers or PSS partners | End-of-sale / end-of-support dates by PID, serial, or software release | `id.cisco.com`, `apix.cisco.com` |
| NVD CVE API 2.0 | No (optional key raises rate) | Anyone | CVEs with CPE match lists | `services.nvd.nist.gov` |

The most useful finding for Network Analysis: **Advisory matching needs no Cisco key**. Cisco's CSAF files can be fetched without auth, come with an index and a change feed, are signed, and list every affected IOS, IOS-XE and NX-OS release. What CSAF lacks (SIR, first-fixed release) needs the openVuln API and a key. **EoX data needs a support contract** (SNTC or PSS); there is no keyless Cisco source for it.

## 1. Cisco PSIRT openVuln API

### Authentication

- Register an app at the API Console, `https://apiconsole.cisco.com`, logging in with a Cisco.com ID; the page offers a Register button for people without one. Application type is "service", grant type is "Client Credentials", and you select "Cisco PSIRT openVuln API" and agree to the terms of service. The page names no contract or entitlement requirement. ([PSIRT authentication](https://developer.cisco.com/docs/psirt/authentication/))
- Token: OAuth 2.0 client credentials, `POST https://id.cisco.com/oauth2/default/v1/token` with `client_id`, `client_secret`, `grant_type=client_credentials`. The sample response shows `"expires_in":3600` (one hour). ([PSIRT authentication](https://developer.cisco.com/docs/psirt/authentication/)) The token is a bearer JWT with scope `read:advisories`. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/))
- All calls must use HTTPS. ([PSIRT authentication](https://developer.cisco.com/docs/psirt/authentication/))
- Apps registered before 2023-03-01 used `cloudsso.cisco.com` and `api.cisco.com`; those were scheduled for deprecation by 2023-09-30. New apps use `id.cisco.com` and `apix.cisco.com`. ([API changelog](https://developer.cisco.com/docs/psirt/api-changelog), [OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/))
- The PSIRT authentication page warns that "current registered applications will be deprecated in coming months" and links a migration guide. What that next migration changes is **unverified**. ([PSIRT authentication](https://developer.cisco.com/docs/psirt/authentication/))
- Checked: an unauthenticated `GET https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.9.1` returns HTTP 403, so no endpoint works without a token.
- That the Client ID and Secret never expire is stated for Support API apps registered in the same console ([Support APIs application registration](https://developer.cisco.com/docs/support-apis/application-registration/)); for openVuln apps it is **unverified**.

### Endpoints for "Advisories affecting version X"

Base URL `https://apix.cisco.com/security/advisories/v2`. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/))

| Purpose | Request |
|---|---|
| Advisories affecting a version | `GET /OSType/{OSType}?version=<v>`, with `OSType` one of `aci`, `ios`, `iosxe`, `nxos`, `asa`, `ftd`, `fmc`, `fxos` |
| ... narrowed to an NX-OS platform | add `&platformAlias=NEXUS9000` (values for NX-OS: `MDS9000`, `NEXUS1000V`, `NEXUS3000`, `NEXUS5000`, `NEXUS6000`, `NEXUS7000`, `NEXUS9000`) |
| Valid versions Cisco knows | `GET /OS_version/OS_data?OSType=nxos` returns `nos_type`, `nos_version`, `platform_name` |
| Platform aliases | `GET /platforms?OSType=nxos` |

Optional query parameters on `/OSType/{OSType}`: `advisoryId`, `summaryDetails`, `productNames`, `startDate`/`endDate` (`yyyy-mm-dd`), `pageIndex`, `pageSize` (1–100). `platformAlias` applies only to `nxos`, `asa`, `ftd`, `fxos`. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/), [OS_version/OS_data](https://developer.cisco.com/docs/psirt/os_versionos_data), [Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software))

Examples from Cisco: `.../OSType/iosxe?version=17.2.1`, `.../OS_version/OS_data?OSType=ios`, `.../platforms?OSType=nxos`. ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software))

The older `/ios` and `/iosxe` endpoints are tagged "Sunset Endpoints"; use `/OSType/{OSType}`. ([iosxe endpoint](https://developer.cisco.com/docs/psirt/iosxe/)) The `/cvrf/` endpoints were retired on 2022-08-05 and return HTTP 410. ([API changelog](https://developer.cisco.com/docs/psirt/api-changelog))

**Coverage limits that matter for NX-OS:** the version endpoints cover NX-OS and NX-OS in ACI mode only for Advisories from July 2019 onward. ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software)) No such limit is stated for IOS or IOS-XE.

The version endpoints are how the API "query[s] the Cisco Software Checker", so they return the same answers as the web tool. ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software))

When nothing matches, a 200 response carries `errorCode` `NO_IOS_AFFECTING_ADVISORIES_FOUND` or `INVALID_IOS_VERSION` ("IOS version not found") instead of Advisories. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/)) So an unknown version string is reported, not silently treated as clean.

### Response fields (severity and identity)

Each Advisory in the response has: `advisoryId`, `advisoryTitle`, `bugIDs`, `ipsSignatures`, `cves`, `cvrfUrl`, `csafUrl`, `cvssBaseScore`, `cwe`, `firstPublished`, `lastUpdated`, `status`, `version`, `productNames`, `publicationUrl`, **`sir`** (Security Impact Rating, for example `"High"`), `summary`. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/)) Severity filter values elsewhere in the API are `critical`, `high`, `medium`, `low`, `informational`. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/), error `INVALID_SEVERITY`)

Version queries also return **`firstFixed`**, an array of release strings such as `17.3.1w`, `17.3.2a`, `17.3.6`. ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software)) Since 2023-08-22 they also return an **`smu`** field. ([API changelog](https://developer.cisco.com/docs/psirt/api-changelog))

In Cisco's example, `cves` and `bugIDs` are single strings (`"CVE-2022-20714"`, `"CSCvy48962"`); whether several values come as a JSON array or a delimited string is **unverified**. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/))

### Feature and configuration conditions

The openVuln response has **no structured field** saying which feature or configuration must be enabled for a device to be affected; the field list above is complete per Cisco's schema, and the by-software page mentions no such conditions. ([OSType endpoint](https://developer.cisco.com/docs/psirt/ostypeostype/), [Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software)) The condition exists only as prose in the Advisory's "Vulnerable Products" section (see the CSAF section below), reachable through `summary` (HTML) or the `csafUrl`/`publicationUrl` document.

### Rate limits and terms

- Per application: **5 calls per second, 30 calls per minute, 5000 calls per day**. Over the limit returns HTTP 429 with `X-Mashery-Error-Code: ERR_403_DEVELOPER_OVER_RATE` and a `Retry-After` header. Responses page with `pageIndex`/`pageSize` and a `paging` object (`next`, `prev`, `count`). ([Pagination and rate limits](https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits))
- Caching: Cisco lists "not using a local cached copy of data" as a common cause of rate-limit errors ([Pagination and rate limits](https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits)) and its FAQ says "We recommend following best practices for rate-limiting and using local caching of data." ([PSIRT FAQ](https://developer.cisco.com/docs/psirt/faq/)) So Cisco expects results to be cached.
- The terms of service shown at app registration could not be read without logging in: **unverified**. The general [Cisco API License Terms](https://developer.cisco.com/site/license/cisco-api-license) and [Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf) were found by search; per the search summary they bar storing confidential or protected data without authorization and bar using API content as AI/ML training data. No clause forbidding a local cache of public Advisory data was found, but the full texts were not read here (**unverified**).

## 2. Version strings: `show version` versus what Cisco's data expects

Cisco's own reference guide shows that IOS-XE `show version` prints the release **twice, in two formats** ([IOS and NX-OS Software Release Reference Guide](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide)):

- 16.x and later: headline `Cisco IOS XE Software, Version 16.09.01` (zero-padded), and on the IOSd line `Version 16.9.1` (not padded).
- 3.x trains: headline `Cisco IOS XE Software, Version 03.10.00.S - Extended Support Release`, and IOSd `Version 15.3(3)S`. The 3.x release name embeds the IOSd (classic IOS) version; release notes carry mapping tables.

Classic IOS 15 versions are `major.minor(feature)` plus a train letter and optional rebuild: `15.6(3)M`, `15.1(1)T2`, `15.2(2a)E`. NX-OS uses `major.minor(maintenance)` with an optional platform designator and sub-release, such as `7.3(3)D1(1)`. ([Release Reference Guide](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide))

NX-OS `show version` prints `NXOS: version 9.2(2) [build 9.2(1.47)]`; in NX-API JSON that is `kickstart_ver_str`. ([Nexus 9000 NX-API CLI reference, show version](https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/version-commands)) Older releases print `kickstart: version 6.2(18)` and `system: version 6.2(18)`. ([Release Reference Guide](https://sec.cloudapps.cisco.com/security/center/resources/ios_nx_os_reference_guide)) Newer 10.x releases print a suffix such as `[Maintenance Release]` (seen only in a community post, **unverified** from Cisco docs).

What Cisco's data uses (checked in CSAF files, and in Cisco's API examples):

| Platform | In Cisco data | In `show version` | Normalisation needed |
|---|---|---|---|
| IOS-XE 16/17 | `17.12.1a`, `16.3.10` (no padding) | Headline `Cisco IOS XE Software, Version 16.09.01`; IOSd line `Version 16.9.1` (Cisco's example) | Strip leading zeros from each dotted part, or read the IOSd line |
| IOS (classic) | `15.2(7)E7`, `15.2(6)E0a` | `..., Version 15.2(7)E7, RELEASE SOFTWARE (fc1)` (typical form, **unverified** from a Cisco page) | Take the token after `Version` up to the comma |
| NX-OS | `9.3(10)`, `6.0(2)A8(4a)`, `10.3(1)` | `NXOS: version 9.3(10)` plus optional `[build ...]` or `[... Release]` | Drop the bracketed suffix |

Sources for the "In Cisco data" column: the CSAF files checked below, and openVuln examples `17.2.1`, `17.3.2a` ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software)) and `7.0(3)F1(1)` ([OS_version/OS_data](https://developer.cisco.com/docs/psirt/os_versionos_data)). Cisco's openVulnQuery README gives `--ios 15.6\(2\)SP` and `--nxos 8.3(1)`. ([openVulnQuery](https://github.com/CiscoPSIRT/openVulnQuery)) Whether openVuln accepts the zero-padded IOS-XE form is **unverified**; `/OS_version/OS_data` lists the exact strings it accepts, and an unknown string returns `INVALID_IOS_VERSION`.

The IOS-XE 3.x trains (`03.10.00.S`) were not seen in any CSAF file checked; how they appear there is **unverified**.

## 3. Public CSAF files (no key)

Checked on 2026-11-20, all without authentication:

- **Provider metadata**: `https://www.cisco.com/.well-known/csaf/provider-metadata.json` (HTTP 200). Role `csaf_trusted_provider`, publisher "Cisco PSIRT", one distribution `directory_url` `https://www.cisco.com/.well-known/csaf/`, and a PGP key (fingerprint `081e38f3eb110265a214514124b3ec61e4205802`) at `https://cscrdr.cloudapps.cisco.com/cscrdr/security/center/files/Cisco_PSIRT_PGP_Public_Key.asc`. No ROLIE feed is listed.
- **Index**: `https://www.cisco.com/.well-known/csaf/index.txt` lists 2,896 files, by year folder, from 2017 to 2026. Older Advisories are not in the directory.
- **Change feed**: `https://www.cisco.com/.well-known/csaf/changes.csv`, newest first, one `path,timestamp` per line (for example `2026/cisco-sa-...json,2026-11-20T15:13:58Z`). This allows incremental sync.
- **Files**: `https://www.cisco.com/.well-known/csaf/<year>/<advisory-id-lowercase>.json`. Paths are **lowercase**: the mixed-case Advisory id returns 404.
- **Integrity**: each file has a `.asc` signature and a `.sha512` hash beside it (both HTTP 200); `.sha256` returns 404.
- The per-Advisory `csafUrl` the openVuln API returns (`tools.cisco.com/security/center/contentjson/...`) redirects (302) to `sec.cloudapps.cisco.com/security/center/contentjson/.../csaf/<id>.json`, which also serves the file without auth.

Cisco's statement that it is a CSAF publisher, and the same provider-metadata URL, are in its [statement of use to the OASIS CSAF committee](https://lists.oasis-open.org/archives/csaf/202208/msg00003.html) and a [Cisco DevNet knowledge-base article](https://community.cisco.com/t5/devnet-general-knowledge-base/what-is-the-common-security-advisory-framework-csaf/ta-p/4743320). CVRF was supported only until 2023-12-31; Cisco recommends CSAF. ([PSIRT overview](https://developer.cisco.com/docs/psirt/), [API changelog](https://developer.cisco.com/docs/psirt/api-changelog))

### What a CSAF file holds (checked in six files)

Files checked: `2023/cisco-sa-iosxe-webui-privesc-j22saa4z.json`, `2023/cisco-sa-nxos-cli-cmdinject-euqvk9u.json`, `2026/cisco-sa-ios-xmcp-thbar34t.json`, `2026/cisco-sa-iosxe-lobby-privesc-kwxbqjy.json`, `2026/cisco-sa-xe-webui-dos-ptaodaww.json`, `2025/cisco-sa-iox-dos-95fqnf7b.json`, all under `https://www.cisco.com/.well-known/csaf/`.

- **Product tree**: `vendor` Cisco → `product_family` → `product_version` (train) → `service_pack` (exact release) with a `product_id`. Examples: family `Cisco IOS XE Software` → `17.12` → `17.12.1a`; family `IOS` → `15.2E` → `15.2(6)E0a`; family `Cisco NX-OS Software` → `6.0(2)A8` → `6.0(2)A8(4a)`. Family names are not uniform (`IOS` versus `Cisco IOS XE Software`), so match by name per family.
- **NX-OS platforms**: the NX-OS file adds `product_name` entries such as "Cisco Nexus 9000 Series Switches" and 194 `installed_on` relationships ("Cisco NX-OS Software 6.0(2)A8(1) when installed on Cisco Nexus 3000 Series Switches"). IOS and IOS-XE files have no relationships: the version alone decides.
- **Status**: every vulnerability uses only `product_status.known_affected`. None of the six has `fixed`, `first_fixed` or `known_not_affected`. A version not listed is therefore "not known affected", not "known fixed".
- **Severity**: `scores[].cvss_v3` with `baseScore`, `baseSeverity` (for example `CRITICAL`), `vectorString`, `version` `3.1`. **No Security Impact Rating field**: SIR appears only in prose, and `document.aggregate_severity` is absent in all six.
- **Identity**: `vulnerabilities[].cve`, and Cisco bug ids in `ids[]` (`system_name` "Cisco Bug ID"). One file can hold several vulnerabilities.
- **Feature conditions**: only as prose in the document note titled "Vulnerable Products", often with the exact `show running-config` check. For example the IOS-XE web UI Advisory says the device is affected "if the web UI feature is enabled", checked with `show running-config | include ip http server|secure|active`, and not exploitable over HTTP if `ip http active-session-modules none` is also present. The XMCP Advisory gives `show running-config | include service-routing xmcp listen`. These are not machine-readable.
- **Remediation**: `remediations[]` with category `vendor_fix` and generic text; no fixed release.
- Every vulnerability carries a note "Affected Product Comprehensiveness: Complete."

**Answer**: yes, CSAF can be fetched without auth, has an index and change feed, and carries enough product and version data to decide offline whether a Visited Device's IOS, IOS-XE or NX-OS release is listed as affected. It does not give SIR or first-fixed releases, and feature conditions need a human (or per-Advisory rules written by hand). If Analysis can live with CVSS severity instead of SIR, and without "upgrade to" advice, **it needs no Cisco API key**.

Licence or terms for reuse of CSAF files: each file carries a "Legal Disclaimer" note ("provided on an AS IS basis ... A standalone copy or paraphrase of the text of this document that omits the distribution URL is an uncontrolled copy"). No other terms were found. Whether a local copy is permitted beyond that is **unverified**, though the files are published for machine consumption.

## 4. Cisco Software Checker

The web tool is `https://sec.cloudapps.cisco.com/security/center/softwarechecker.x` (checked: HTTP 200, HTML). It covers ASA, FMC, FTD, FXOS, IOS, IOS XE, NX-OS and NX-OS in ACI mode. ([PSIRT overview](https://developer.cisco.com/docs/psirt/)) It returns each Advisory affecting a release and its "First Fixed" release, plus a "Combined First Fixed" release (quoted in the "Fixed Software" note of the CSAF files checked). The **supported API behind it is the openVuln version endpoints** above: "The Cisco PSIRT OpenVuln API allows users to query the Cisco Software Checker." ([Obtain advisory by software](https://developer.cisco.com/docs/psirt/obtain-advisory-by-software)) No other official version-to-Advisory API was found. The web tool's internal calls are not documented and should not be used.

## 5. Cisco EoX API (Support APIs)

- **Entitlement**: "Cisco Support APIs are available only to Cisco Smart Net Total Care (SNTC) customers" and Partner Support Service (PSS) partners. Access is granted per Cisco.com user. Customers are onboarded through the SNTC portal by their Delegated Administrator, who grants API access in Cisco Services Access Management. Partners request access with a PSS contract number; a TAC engineer grants it, which can take up to 48 hours, and the partner organisation needs at least one valid SNTC contract with the customer. Only then can an app be registered in the API Console. ([Support APIs onboarding](https://developer.cisco.com/docs/support-apis/user-onboarding-process/), [Application registration](https://developer.cisco.com/docs/support-apis/application-registration/))
- **Auth**: OAuth2 client credentials at `https://id.cisco.com/oauth2/default/v1/token`; default token lifetime 3600 s; API host `apix.cisco.com`. ([Support APIs authentication](https://developer.cisco.com/docs/support-apis/authentication/)) Client ID and Secret "don't expire". ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/))
- **Endpoints** (base `https://apix.cisco.com/supporttools/eox/rest/5/`, optional `responseencoding=json|xml`) ([EoX API](https://developer.cisco.com/docs/support-apis/eox/)):
  - `EOXByProductID/{pageIndex}/{productID}`: up to 20 comma-separated PIDs (max 250 chars); exact match except wildcards (min 3 chars); `WIC-1T` and `WIC-1T=` are different PIDs.
  - `EOXBySerialNumber/{pageIndex}/{serialNumber}`: up to 20 serials.
  - `EOXBySWReleaseString/{pageIndex}?input1=<release>,<OSType>` ... `input20`: OSType values include `IOS`, `IOS-XE`, `NX-OS`. Sample: `input1=12.4%2815%29T,IOS`.
  - `EOXByDates/{pageIndex}/{startDate}/{endDate}`.
- **Response fields**: `EOLProductID`, `ProductIDDescription`, `LinkToProductBulletinURL`, `EOXExternalAnnouncementDate`, `EndOfSaleDate`, `EndOfSWMaintenanceReleases`, `EndOfSecurityVulSupportDate`, `EndOfRoutineFailureAnalysisDate`, `EndOfServiceContractRenewal`, `LastDateOfSupport`, `EndOfSvcAttachDate`, `UpdatedTimeStamp`, `EOXMigrationDetails` (replacement PID and strategy), and `EOXError` (`ErrorID`, `ErrorDescription`). ([EoX API](https://developer.cisco.com/docs/support-apis/eox/)) Error `SSA_ERR_036` means "not authorized to access the EoL web service". ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- **Rate limits**: none documented by Cisco. A community post claims 5000 calls per day per credential (**unverified**). ([community thread](https://community.cisco.com/t5/smart-net-total-care-portal-and-collector-discussions/can-t-retrieve-token-for-app-eox-support-api/m-p/4913947))
- **Quality caveat**: community users report `EOXBySWReleaseString` returns very large, hard-to-match results and that a product with no announced EoL returns an error (`SSA_ERR_026`) instead of data. These are forum reports, **unverified** from Cisco docs. ([community thread](https://community.cisco.com/t5/services-discussions/get-eox-by-software-release-string/td-p/4811065))
- **No keyless EoX source** was found. Cisco publishes EoL bulletins as HTML pages (linked from `LinkToProductBulletinURL`), but no machine-readable public feed exists that this session could find (**unverified** negative).

## 6. Python clients

**[openVulnQuery](https://github.com/CiscoPSIRT/openVulnQuery)** (Cisco PSIRT):

- Licence MIT, "Copyright (c) 2025, Cisco Systems, Inc." (`LICENSE` in the repo, checked by clone).
- PyPI latest `1.34`, uploaded 2023-08-06; earlier releases 1.31 (2020-11-16), 1.30 and 1.29 (2018-10-16). Requires `requests` and `argparse`; no `requires_python` and no OS classifiers. ([PyPI JSON](https://pypi.org/pypi/openVulnQuery/json))
- Last commits: 2025-04-18 (licence update) and 2025-06-28 (SLSA publish workflow); last code change 2023-08-05. Not archived. ([repo](https://github.com/CiscoPSIRT/openVulnQuery))
- Already uses `id.cisco.com` and `apix.cisco.com` (`openVulnQuery/_library/config.py`).
- README: "Tested on Python 3.7 and 3.9.2". No mention of Windows.
- Reads credentials from the `CLIENT_ID`/`CLIENT_SECRET` **environment variables**, a JSON `--config` file, or `config.py` (`openVulnQuery/_library/cli_api.py`). That conflicts with this project's rule that secrets are entered at a prompt and never read from the environment or a file.
- Fetches a fresh token on every call ("The resulting OAuth2 Token will be automatically generated on every call to the API", README), which spends rate-limit budget.
- It is a CLI first; it does not cover CSAF directory sync or EoX.

**Conclusion**: do not vendor it. The API surface needed is one token POST and two or three GETs, which a small HTTPS client (the Python standard library or `httpx`/`requests`) covers in well under 200 lines, with credential handling that follows the project's rules. For CSAF, the [CSAF 2.0 standard](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) JSON can be read with the standard library `json`; signature checks need an OpenPGP library (choice not researched here).

Other Python clients for the EoX API were not researched beyond noting that none is published by Cisco (**unverified**).

## 7. Hosts (for an egress fence)

| Host | Used for | Needed when |
|---|---|---|
| `www.cisco.com` | CSAF provider metadata, `index.txt`, `changes.csv`, Advisory JSON, `.asc`, `.sha512` | CSAF route (keyless) |
| `cscrdr.cloudapps.cisco.com` | Cisco PSIRT PGP public key | Once, to fetch the key; better pinned in the repo by fingerprint |
| `sec.cloudapps.cisco.com` | Per-Advisory CSAF via `csafUrl`, Advisory HTML (`publicationUrl`), Software Checker web | Only if following URLs from openVuln responses; not needed for the `/.well-known/csaf/` route |
| `tools.cisco.com` | Older `csafUrl`/`publicationUrl` form; 302 to `sec.cloudapps.cisco.com` | Avoid by rewriting to the `www.cisco.com` path |
| `id.cisco.com` | OAuth2 token | openVuln or EoX API |
| `apix.cisco.com` | openVuln API and EoX API | openVuln or EoX API |
| `services.nvd.nist.gov` | NVD CVE API 2.0 | Only if NVD is used |

Retired, not needed: `api.cisco.com`, `cloudsso.cisco.com`. ([API changelog](https://developer.cisco.com/docs/psirt/api-changelog))

So the exact lists are: **keyless CSAF** `www.cisco.com` (plus `cscrdr.cloudapps.cisco.com` once, or pin the key); **openVuln** `id.cisco.com`, `apix.cisco.com`; **EoX** `id.cisco.com`, `apix.cisco.com`.

## 8. NVD as a fallback

The NVD CVE API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`) works without a key (checked: HTTP 200). Without a key the limit is 5 requests per rolling 30 seconds; with a free key it is 50, and NIST still recommends sleeping several seconds between requests. A key needs an organisation name, email and organisation type, and acceptance of the Terms of Use; products must say they use NVD data but are "not endorsed or certified by the NVD". ([NVD Start Here](https://nvd.nist.gov/developers/start-here), [Request an API key](https://nvd.nist.gov/developers/request-an-api-key), [Terms of Use](https://nvd.nist.gov/developers/terms-of-use); the NVD site is a script-rendered page, so these were read through search summaries, not directly.) For Cisco, the CVE records come from Cisco's own CNA (checked: CVE-2026-20301 has `sourceIdentifier` `psirt@cisco.com`, status `Analyzed`, and lists explicit per-release CPEs, 140 in its first configuration node, like `cpe:2.3:o:cisco:ios:15.2\(2\)e8`), so NVD adds little that Cisco's CSAF lacks, uses lower-cased, escaped version strings that need their own normalisation, and carries no SIR or feature conditions. Since 2026-04-15 NIST enriches only priority CVEs (CISA KEV, federal and EO 14028 critical software) and marks the rest "Lowest Priority - not scheduled for immediate enrichment", so CPE data for new Cisco CVEs may be missing. ([NIST Updates NVD Operations](https://www.nist.gov/node/1910421)) **NVD is a worse source than Cisco's CSAF for Cisco devices.**

## What the downstream tickets need

- **How Cisco API keys are supplied and kept**: Advisory matching can run with **no key** (CSAF). A key is needed only for SIR and first-fixed data (openVuln) or for EoX. Both are an OAuth2 Client ID + Client Secret pair from the API Console, exchanged at `id.cisco.com` for a one-hour bearer token. openVuln needs only a Cisco.com account; EoX needs SNTC or PSS entitlement. The Client Secret is a long-lived secret, so it falls under the same handling question as a Credential Set password.
- **When a device counts as vulnerable**: IOS-XE version strings need leading zeros stripped (`17.09.04a` → `17.9.4a`) or the IOSd line read; NX-OS needs bracketed suffixes dropped and, for openVuln, a `platformAlias` (for CSAF, a mapping from the chassis to "Cisco Nexus N000 Series Switches"). Severity: openVuln gives SIR and `cvssBaseScore`; CSAF gives only CVSS v3.1 base score and severity. CVE ids and bug ids come from both. Feature conditions exist only as prose with `show running-config` checks; neither source makes them machine-readable. CSAF lists only `known_affected`, so "not listed" means "not known affected".
- **When Analysis runs and how it reaches Cisco**: hosts as in section 7. openVuln: 5/s, 30/min, 5000/day per app; Cisco recommends local caching. CSAF: one `index.txt` plus `changes.csv` gives incremental sync of about 2,900 files; no documented rate limit. Analysis could therefore sync CSAF before or after a Run and match offline, with no device data leaving the operator's machine; the openVuln route sends each software version (not device names) to Cisco.
- **Which configuration, lifecycle and consistency Checks ship**: EoX data needs SNTC or PSS entitlement and an API Console app; there is no keyless source. Lookups by PID (from `show inventory`) or by software release with OSType `IOS`, `IOS-XE`, `NX-OS`; up to 20 inputs per call; rate limits undocumented.
