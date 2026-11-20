# Cisco EoX and Software Suggestion APIs: access, inputs and bulk mirroring

Research for [Cisco EoX and Software Suggestion APIs: access, inputs and bulk mirroring](https://github.com/b-git-hub/network-analyser/issues/86), a child of [Map: Network Analysis, the way to a build spec](https://github.com/b-git-hub/network-analyser/issues/74). It builds on [Cisco Advisory and lifecycle data sources](https://github.com/b-git-hub/network-analyser/issues/75) and the recommended-release section of [Cisco hardening baselines for IOS-XE and NX-OS](https://github.com/b-git-hub/network-analyser/issues/76).

Findings dated **2026-11-20**. Every fact cites the page it came from. "Checked" means this session fetched the URL itself on 2026-11-20. Anything marked **unverified** could not be confirmed from a Cisco primary source. No account was created, no credentials were used and nothing behind a login was read. The only live calls sent dummy values (`client_id=dummy-client`, a made-up bearer token, a date range and an mdfId copied from Cisco's own documentation), so no device data and no personal details went to Cisco.

Terms follow [GLOSSARY.md](../../GLOSSARY.md). Two terms need a flag:

- **"Suggested release" conflicts with the glossary.** GLOSSARY.md lists "suggested release" under _Avoid_ for **Upgrade Target** (the newest release in a device's own Train that no Critical or High Advisory names). Cisco's "Cisco Suggested" release (`isSuggested: "Y"`) is a different thing: Cisco's own pick, "based on factors such as stability and adoption rate". This note calls it the **Cisco Suggested release** and never uses it to mean Upgrade Target. The Check ticket should decide on a glossary term for it.
- **EoX** (end-of-sale / end-of-life) is not in the glossary yet.

## Sources

| Source | URL | Fetched |
|---|---|---|
| Support APIs overview | https://developer.cisco.com/docs/support-apis/ | 2026-11-20 |
| EoX API v5 reference | https://developer.cisco.com/docs/support-apis/eox/ | 2026-11-20 |
| EoX Service API Reference v4.0 (legacy PDF, 2015-10-29) | https://pubhub.devnetcloud.com/media/support-apis/docs/eox-api-user-guide_v4_0.pdf | 2026-11-20 |
| Software Suggestion API reference | https://developer.cisco.com/docs/support-apis/software-suggestion/ | 2026-11-20 |
| Product Information API reference | https://developer.cisco.com/docs/support-apis/product-information/ | 2026-11-20 |
| Support APIs user onboarding | https://developer.cisco.com/docs/support-apis/user-onboarding-process/ | 2026-11-20 |
| Guide to Enabling Customer Access to Services APIs (PDF, 2018-09-24) | https://pubhub.devnetcloud.com/media/support-apis/docs/Guide-to-Assigning-Customer-API-Roles.pdf | 2026-11-20 |
| Support APIs application registration | https://developer.cisco.com/docs/support-apis/application-registration/ | 2026-11-20 |
| Support APIs authentication | https://developer.cisco.com/docs/support-apis/authentication/ | 2026-11-20 |
| Support APIs developer support | https://developer.cisco.com/docs/support-apis/developer-support/ | 2026-11-20 |
| Support APIs changelog | https://developer.cisco.com/docs/support-apis/api-changelog/ | 2026-11-20 |
| API Console FAQs | https://apiconsole.cisco.com/docs/read/overview/FAQs | 2026-11-20 |
| API Console OAuth 2.0 topics | https://apiconsole.cisco.com/docs/read/overview/Oauth_20_Topics | 2026-11-20 |
| API Console navigating (apps, keys, delete) | https://apiconsole.cisco.com/docs/read/overview/Navigating_Cisco_API_Console | 2026-11-20 |
| API Console migrating applications | https://apiconsole.cisco.com/docs/read/overview/Migrating_Applications | 2026-11-20 |
| Baseline API License Terms (EDCS-25972489 v1.1, 2026-04-02) | https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf | 2026-11-20 |
| Data Access Terms (EDCS-25825101 v1.3, 2026-04-09) | https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Data-Access-Supplemental-Terms.pdf | 2026-11-20 |
| Cisco API License Terms v1.2 (2024-07-04) | https://developer.cisco.com/site/license/cisco-api-license | 2026-11-20 |
| IOS XE 17.6.x EoL bulletin | https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-6-x-eol.html | 2026-11-20 |
| Live checks with dummy values | `id.cisco.com` token endpoint and its `/.well-known/oauth-authorization-server`, `apix.cisco.com` EoX and Software Suggestion paths | 2026-11-20 |

Not reachable without a login, so not read: the EoX and Software Suggestion WADL files and `Token_Access.pdf` on `apiconsole.cisco.com/files/` (HTTP 403, sign-in page), and the Cisco Community threads (HTTP 403 to this session).

## Summary

| Question | Short answer |
|---|---|
| 1. EoX bulk mirroring | **Yes, documented.** `EOXByDates` with no `eoxAttrib` returns every record whose update timestamp falls in the range, so a range from before the first record to today pulls the whole EoX database without sending a PID, serial or release. Current size, the real page size and the rate limits are **unverified**. Release-to-EoX matching does **not** work offline: records carry no release-string field. |
| 2. Software Suggestion v2 | SNTC or PSS, like every Support API. Inputs are base PIDs (up to 10) **or mdfIds** (up to 10). There is no "list all" call, so mirroring without device data means asking for a fixed list of PIDs or mdfIds that the tool carries, not one built from the Scope. |
| 3. Onboarding and least privilege | SNTC Delegated Administrator gives the user the "API Developer" role in CSAM (can be time-boxed); the user registers a "Service" app with Client Credentials and ticks only EoX and Software Suggestion. Secret never expires; token lasts 3600 s; revoke by deleting the key or app. |
| 4. Hosts | `id.cisco.com` (token, `/oauth2/default/v1/token`) and `apix.cisco.com` (both APIs). Nothing else at run time. |
| 5. Terms | No clause on caching. Redistribution of the APIs or access to them is banned, and offering third parties something "substantially similar" is banned. Cisco may monitor API use; nothing published on logging or keeping request inputs. Credentials must not be embedded in open-source projects. |

## 1. EoX API v5: bulk mirroring

### Can the whole dataset be pulled without device data?

- `GET https://apix.cisco.com/supporttools/eox/rest/5/EOXByDates/{pageIndex}/{startDate}/{endDate}` "Returns all active and inactive EoX records for all products with the specified `eoxAttrib` value within the `startDate` and `endDate` values, inclusive. If you do not specify an `eoxAttrib` value, this method returns records with an updated time stamp within the specified date range." ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- Cisco adds that filtering by attribute "allows you to target specific date ranges within each attribute **without having to pull the entire database**", which treats a full pull as a normal use. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/); same wording since the v4.0 guide, [EoX v4.0 PDF](https://pubhub.devnetcloud.com/media/support-apis/docs/eox-api-user-guide_v4_0.pdf))
- So a full mirror is a series of `EOXByDates` calls over a wide date range, and the only inputs sent are two dates and a page number. **No PID, serial or release leaves the PC.**
- Whether Cisco caps the date span of one `EOXByDates` call is **unverified**; no cap is documented. If one exists, the range can be split by year.
- `eoxAttrib` values: `EO_EXT_ANNOUNCE_DATE`, `EO_SALES_DATE`, `EO_FAIL_ANALYSIS_DATE`, `EO_SVC_ATTACH_DATE`, `EO_SW_MAINTENANCE_DATE`, `EO_SECURITY_VUL_SUPPORT_DATE`, `EO_CONTRACT_RENEW_DATE`, `EO_LAST_SUPPORT_DATE`, `UPDATE_TIMESTAMP` (default). ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- A second keyless-of-device-data route exists: `EOXByProductID` accepts wildcards (minimum 3 characters, for example `*VPN*`, `VPN*`). A family prefix such as `C9300*` reveals a product family, not a device. `EOXByDates` makes this unnecessary. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))

### Size and paging

- Paging: every method takes `pageIndex` (integer, up to 5 digits, so at most 99,999 pages); the response has `PaginationResponseRecord` with `PageIndex`, `LastIndex` (total pages), `TotalRecords` and `PageRecords`. To read everything, call with `PageIndex` 1 to `LastIndex`. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- **Page size is inconsistent in Cisco's own documentation.** The parameter tables say "a maximum of 50 records per page are returned", but the `EOXByDates` sample shows `PageRecords` 1000, and the `PaginationResponseRecordType` sample shows `LastIndex` 89, `TotalRecords` 88188, `PageRecords` 1000. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/)) The real page size is **unverified**.
- **Record count is unverified.** The only figure Cisco shows is that sample (88,188 records); its date and whether it was a whole-database query are not stated. Records exist only for products with an EoX announcement: a PID with none gives error `SSA_ERR_026` "EOX information does not exist for the following product ID(s)". ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- One PID can have **several records**, one per migration path; they differ only in `EOXMigrationDetails` and share the same `UpdatedTimeStamp`. A mirror must key on PID plus migration details, not PID alone. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))

### Rate limits and sync time

- **Cisco does not publish numbers for EoX or Software Suggestion.** What is documented is the shape of the limits: Support APIs return HTTP **403** with `ERR_403_DEVELOPER_OVER_QPS` ("too many times in one second"), `ERR_403_DEVELOPER_OVER_RATE` ("too many times in the rate limiting period (1 day)"), or "Rate Limit Exceeded" ("over capacity"). So there is a per-second limit and a per-day limit, per API key. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/), same codes on [Product Information API](https://developer.cisco.com/docs/support-apis/product-information/)) Note these arrive as 403, not 429.
- The figures 10 calls per second and 5,000 calls per day per app appear only in a third-party blog and a Cisco Community post (**unverified**). The Baseline API Terms let Cisco set and change such limits at its discretion. ([Baseline API Terms §4](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf))
- **Estimate, all inputs unverified:** at about 90,000 records, a full sync is about 90 calls at 1,000 per page or about 1,800 calls at 50 per page. Either fits inside 5,000 calls a day; at 10 calls a second the request budget alone is 9 seconds to 3 minutes, before network latency. A **daily delta** is `EOXByDates` over the last few days with the default `UPDATE_TIMESTAMP`, normally one page. Whether a withdrawn or deleted record ever shows up in a delta is **unverified**, so a periodic full sync is the safe pattern.

### Coverage: chassis, modules, software

- The API gives EoX data "for both hardware and software". ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- Records are per orderable PID, so modules and spares are covered as well as chassis. Cisco's own samples include a WAN interface card (`WIC-1T=`), a chassis (`CISCO1811/K9`), and software PIDs (`S280IPBK9-12424T=`, "Cisco 2801 IOS IP BASE"). ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- Matching is exact: `WIC-1T` and `WIC-1T=` (the spare) "are different PIDs that can yield different results". ([EoX API](https://developer.cisco.com/docs/support-apis/eox/)) Offline matching must handle the trailing `=`.

### Fields

`EOXRecord` holds ([EoX API](https://developer.cisco.com/docs/support-apis/eox/)):

| Field | Meaning (Cisco's wording, shortened) |
|---|---|
| `EOLProductID` | The PID |
| `ProductIDDescription` | Product description |
| `ProductBulletinNumber`, `LinkToProductBulletinURL` | The EoL bulletin |
| `EOXExternalAnnouncementDate` | Public announcement |
| `EndOfSaleDate` | Last date to order |
| `EndOfSWMaintenanceReleases` | Last date for software maintenance releases or bug fixes |
| `EndOfSecurityVulSupportDate` | Last date for a planned release or remedy for a security vulnerability |
| `EndOfRoutineFailureAnalysisDate` | Last routine failure analysis |
| `EndOfServiceContractRenewal` | Last date to renew a service contract |
| `LastDateOfSupport` | After this, the product is obsolete |
| `EndOfSvcAttachDate` | Last date to add to a service contract |
| `UpdatedTimeStamp` | When the record was created or last changed |
| `EOXMigrationDetails` | `PIDActiveFlag`, `MigrationInformation`, `MigrationOption`, `MigrationProductId` (replacement PID), `MigrationProductName`, `MigrationStrategy`, `MigrationProductInfoURL` |
| `EOXInputType`, `EOXInputValue` | Echo of the method and the inputs sent |
| `EOXError` | `ErrorID`, `ErrorDescription`, and for serial and release queries `ErrorDataType` / `ErrorDataValue` |

Dates are objects `{ "value": "YYYY-MM-DD", "dateFormat": "YYYY-MM-DD" }`, and an empty date is a single space `" "`. ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))

### What `EOXBySWReleaseString` returns

- `GET .../EOXBySWReleaseString/{pageIndex}?input1=<release>,<OSType>` up to `input20`; `OSType` is optional and its list includes `IOS`, `IOS-XE`, `NX-OS`, `IOS XR`, `UCS NX-OS`. It "normally returns a set of **software PIDs**". ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- Cisco's only example is IOS: `12.4(15)T,IOS` returns **989** records, each a software PID for one platform and feature set (for example `S280IPBK9-12424T=`, `S54AVSK9U-12424T`). ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- **The record has no release-string field.** The release only appears in `EOXInputValue`, the echo of what was sent. So a mirror pulled with `EOXByDates` cannot be matched to a device's running release without parsing `ProductIDDescription` or the software PID's name. Offline release matching is **not supported by the data model**; offline PID matching is.
- What the call returns for IOS-XE and NX-OS releases is **unverified** (no example; testing needs a key). One sign that coverage may be thin: Cisco's IOS XE 17.6.x EoL bulletin gives dates for "OS SW" but no table of affected part numbers. ([IOS XE 17.6.x EoL bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-6-x-eol.html)) Whether such train-level bulletins appear in the EoX API, and under which PIDs, is **unverified**.
- Earlier forum reports that this method returns large, hard-to-match results ([Cisco Advisory and lifecycle data sources](https://github.com/b-git-hub/network-analyser/issues/75)) match the 989-record example above.

## 2. Software Suggestion API v2

### Entitlement

- "Cisco Support APIs are available only to Cisco Smart Net Total Care (SNTC) customers and Cisco Partner Support Service (PSS) partners." ([User onboarding](https://developer.cisco.com/docs/support-apis/user-onboarding-process/)) Software Suggestion is listed as one of the Support APIs. ([Support APIs overview](https://developer.cisco.com/docs/support-apis/))
- So it needs **SNTC or PSS**, the same as EoX. No Cisco page says a plain Cisco.com account is enough. Whether Cisco enforces this per API in practice is **unverified**.

### Inputs

All under `https://apix.cisco.com/software/suggestion/v2/suggestions/`; JSON only. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))

| Call | Input | Max per call |
|---|---|---|
| `software/productIds/{productIds}` | Base PIDs, releases **and images** | 10 |
| `releases/productIds/{productIds}` | Base PIDs, releases only | 10 |
| `compatible/productId/{basePID}` | One base PID, optional `currentImage`, `currentRelease`, `supportedFeatures` (up to 10), `supportedHardware` | 1 |
| `software/mdfIds/{mdfIds}` | **mdfIds**, releases and images | 10 |
| `releases/mdfIds/{mdfIds}` | **mdfIds**, releases only | 10 |
| `compatible/mdfId/{mdfId}` | One mdfId, same optional filters | 1 |

All take an optional `pageIndex`.

- A **base PID** is the "manufacturing or chassis product ID". An **mdfId** is the "Id of the device from the Cisco Metadata Framework (MDF)", in practice a product model such as "ASR 903 Route Switch Processor 1". ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- **Neither input is neutral.** A base PID or an mdfId names a product model. Neither names one device (no serial, hostname or address), but a set of them sent from a Run would describe the operator's estate. The `compatible` calls' `currentRelease`, `currentImage` and `supportedHardware` would reveal more, and should not be used if no device data may leave the PC.
- **There is no documented "list all" call** and no family-wide call. Whether a series-level mdfId (the Product Information API returns both `product_name_mdf` and `product_series_mdf`) returns every model in the series is **unverified**. ([Product Information API](https://developer.cisco.com/docs/support-apis/product-information/))
- So "mirroring" Software Suggestion without device data means sending a **fixed list built into the tool** (for example every Catalyst and Nexus base PID or mdfId the tool supports), the same list for every operator, never one derived from the Scope. At 10 per call, a few hundred models is a few dozen calls. Where such a list comes from is open: the Product Information API's `product_ids_mdf` maps PIDs to mdfIds but takes PIDs as input (up to 5). ([Product Information API](https://developer.cisco.com/docs/support-apis/product-information/))

### Result fields

`productList[].product`: `basePID` (absent for mdfId calls), `mdfId`, `productName`, `softwareType` (for example "IOS XE Software"). `productList[].suggestions[]` (`SuggestionType`): `id`, `isSuggested` (`Y`/`N`), `releaseFormat1` (for example `15.1.4M5`), `releaseFormat2` (for example `15.1(4)M5`), `releaseDate` (for example `24 May 2016`), `majorRelease`, `releaseTrain`, `releaseLifeCycle` (samples show `MD` and `ED`), `relDispName`, `trainDispName`, `images[]` (`imageName`, `imageSize`, `featureSet`, `description`, `requiredDRAM`, `requiredFlash`), `errorDetailsResponse`. Top level: `paginationResponseRecord` (`pageIndex`, `lastIndex`, `totalRecords`, `pageRecords`, `selfLink`, `title`), `status`, `errorDetailsResponse` (`errorCode`, `errorDescription`, `suggestedAction`, `inputIdentifier`). Empty or null fields are left out of the JSON. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))

- `releaseTrain` "All compatible release trains are included in the response", so one product can return suggestions in several Trains. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- The meaning of `MD` and `ED` is not defined on the page (**unverified**; they look like Cisco's Maintenance Deployment and Early Deployment labels).

### Which PIDs return nothing

- Cisco describes the API as covering "a growing list of products"; no list is published. ([Support APIs overview](https://developer.cisco.com/docs/support-apis/))
- Errors that mean "no answer": `S3_BASEPID_NO_SUPPORT` ("This basePID is currently not supported"), `S3_MDFID_NO_SUPPORT`, `S3_NO_SOFT_AVL` ("No software available for this product"), `S3_NO_REC_FOUND` ("No records found"), `S3_INV_BASEPID` ("Please enter valid basePID"). ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- Which IOS, IOS-XE and NX-OS PIDs fall in these is **unverified**; testing needs a key. Since inputs must be base (chassis) PIDs, a module or spare PID from `show inventory` should not be expected to return anything (**unverified**).

### Rate limits

Same 403 codes as above, including a 1-day rate period; numbers not published (**unverified**). ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))

### Documentation inconsistencies

The page links a WADL named `Cisco-Software-Suggestion-API-v1_0.wadl` and the changelog says "Software Suggestion v1.0", while every URI is `/v2/`. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/), [API changelog](https://developer.cisco.com/docs/support-apis/api-changelog/)) One sample `selfLink` points at `api-stage.cisco.com`, a staging host that the tool should never call.

## 3. Onboarding and least privilege

### Steps for an SNTC customer

1. The organisation completes SNTC portal onboarding and has a Delegated Administrator (DA). ([User onboarding](https://developer.cisco.com/docs/support-apis/user-onboarding-process/))
2. The user who will hold the key registers for SNTC portal access. ([Customer API roles guide](https://pubhub.devnetcloud.com/media/support-apis/docs/Guide-to-Assigning-Customer-API-Roles.pdf))
3. The DA logs into the Cisco Services Access Management tool (CSAM), chooses Assign Roles to Users, picks the user, expands Smart Net Total Care and assigns the **API Developer** role. The DA can set **a start and end date** on the role to limit access to a time window. ([Customer API roles guide](https://pubhub.devnetcloud.com/media/support-apis/docs/Guide-to-Assigning-Customer-API-Roles.pdf))
4. The user signs in to `https://apiconsole.cisco.com`, My Apps & Keys, Register a New App; Application Type "Service", OAuth 2.0 grant **Client Credentials (only)**; ticks the APIs; accepts the terms of service; Register. The Client ID and Secret are shown on the page and sent by email. ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/), [API Console migrating](https://apiconsole.cisco.com/docs/read/overview/Migrating_Applications))

For PSS partners: request access through the PSS community page with a PSS contract number; a TAC case grants the access; Cisco says this can take up to 48 hours. ([User onboarding](https://developer.cisco.com/docs/support-apis/user-onboarding-process/))

Note that the API Console **emails the Client Secret** on registration. ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/))

### Can one app be limited to EoX and Software Suggestion?

- **Yes.** "A single application registration can be configured to access one-or-more of the individual Support APIs", and at registration you "select the Support APIs that the application should have access to". Users can register several apps. ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/))
- Limits of that: "Each registration represents the identity/role/access/permissions of the API user that created it, with regards to any customer data." The API Developer role is given to the user, not the app, so the same user could register another app with Case, Serial Number to Information or Product Information. The app's own key reaches only the APIs ticked. ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/))
- Adding APIs later: the Support APIs page says you can "add additional API access" to an app, while the API Console FAQ says "you will have to create new application". Cisco's pages disagree; **unverified** which is current. ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/), [API Console FAQs](https://apiconsole.cisco.com/docs/read/overview/FAQs))
- Whether the access token carries a per-API scope is **unverified**. The console's sample token response shows `"scope":"customscope"`. ([API Console OAuth 2.0 topics](https://apiconsole.cisco.com/docs/read/overview/Oauth_20_Topics))

### Grant, token, secret

| Item | Fact | Source |
|---|---|---|
| Grant type | OAuth 2.0 client credentials; one POST, no user interaction | [Authentication](https://developer.cisco.com/docs/support-apis/authentication/) |
| Token request | `POST https://id.cisco.com/oauth2/default/v1/token`, `Content-Type: application/x-www-form-urlencoded`, body `grant_type=client_credentials&client_id=…&client_secret=…` (or the ID and secret as HTTP Basic) | [Authentication](https://developer.cisco.com/docs/support-apis/authentication/), [OAuth 2.0 topics](https://apiconsole.cisco.com/docs/read/overview/Oauth_20_Topics) |
| Token lifetime | 3600 s (sample `expires_in: 3599`); get a new one by repeating the request. No refresh token in this flow | [Authentication](https://developer.cisco.com/docs/support-apis/authentication/), [API Console FAQs](https://apiconsole.cisco.com/docs/read/overview/FAQs) |
| API call | `Authorization: Bearer <token>` to `apix.cisco.com` | [Authentication](https://developer.cisco.com/docs/support-apis/authentication/) |
| Secret expiry | "They do not expire" | [Application registration](https://developer.cisco.com/docs/support-apis/application-registration/) |
| Rotation | No scheduled rotation. If lost or compromised, "delete the key via this portal and generate a new one"; the ID and secret "can be revoked/regenerated in the API Console" | [Application registration](https://developer.cisco.com/docs/support-apis/application-registration/) |
| Revocation | Delete the key (Keys tab, "Delete this key") or the whole app; after deleting an app "the Client ID/Client Secret will no longer be valid". The DA can also end the user's API Developer role in CSAM | [API Console navigating](https://apiconsole.cisco.com/docs/read/overview/Navigating_Cisco_API_Console), [Customer API roles guide](https://pubhub.devnetcloud.com/media/support-apis/docs/Guide-to-Assigning-Customer-API-Roles.pdf) |
| Usage reports | Per-key reports of calls and error codes in the API Console | [Application registration](https://developer.cisco.com/docs/support-apis/application-registration/) |

### How a bad, revoked or expired credential shows up

Checked live with dummy values:

- **Token endpoint, unknown client:** HTTP **400**, JSON `{"errorCode":"invalid_client","errorSummary":"Invalid value for 'client_id' parameter.", …}`. The response carries `x-okta-request-id`, and the discovery document at `https://id.cisco.com/oauth2/default/.well-known/oauth-authorization-server` names issuer `https://id.cisco.com/oauth2/default`, so the token service is Okta-based. It also sets tracking cookies on `.cisco.com`, which the tool can ignore.
- **API, no `Authorization` header:** HTTP **403**, headers `X-Mashery-Error-Code: ERR_403_NOT_AUTHORIZED`, `X-Error-Detail-Header: Not Authorized`, body `Authorization Header is either empty or not found in request`.
- **API, made-up bearer token:** HTTP **403**, `X-Mashery-Error-Code: ERR_403_DEVELOPER_INACTIVE`, `X-Error-Detail-Header: Account Inactive`, body `Developer Inactive`.
- Cisco documents the same 403 family: `ERR_403_NOT_AUTHORIZED` (key not recognised), `ERR_403_DEVELOPER_INACTIVE` (key "not been approved or has been disabled"), and the rate-limit codes. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/)) EoX adds in-body `SSA_ERR_034` ("not authenticated") and `SSA_ERR_036` ("not authorized to access the End-of-Life web service"). ([EoX API](https://developer.cisco.com/docs/support-apis/eox/))
- What a **revoked** secret returns at the token endpoint, and what an **expired** (rather than made-up) token returns at `apix`, are **unverified**: testing needs a real key. Expect `invalid_client` and a 403 `ERR_403_*` respectively. Because authentication failures and rate limits are both HTTP 403 at `apix`, the tool must read `X-Mashery-Error-Code` to tell them apart.

## 4. Hosts

| Host | Path | Used for | Source |
|---|---|---|---|
| `id.cisco.com` | `/oauth2/default/v1/token` | Token | [Authentication](https://developer.cisco.com/docs/support-apis/authentication/), [API Console FAQs](https://apiconsole.cisco.com/docs/read/overview/FAQs) |
| `apix.cisco.com` | `/supporttools/eox/rest/5/…` | EoX API v5 | [EoX API](https://developer.cisco.com/docs/support-apis/eox/) |
| `apix.cisco.com` | `/software/suggestion/v2/suggestions/…` | Software Suggestion | [Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/) |

- `apiconsole.cisco.com` is only for the operator's browser when registering an app, never for the tool.
- `cloudsso.cisco.com` and `api.cisco.com` were the token and API hosts for apps registered before 2023-03-01; new apps use `id.cisco.com` and `apix.cisco.com`. ([API Console migrating](https://apiconsole.cisco.com/docs/read/overview/Migrating_Applications))
- `api-stage.cisco.com` appears in one sample `selfLink` only and is not a production host. ([Software Suggestion API](https://developer.cisco.com/docs/support-apis/software-suggestion/))
- Checked: `apix.cisco.com` answers through a "Mashery Proxy"; neither host redirected the calls made here.

## 5. Terms

Cisco's current [Baseline API License Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf) say they apply "to all use … of any API … made available by Cisco … unless expressly excluded". The text of the API Console's own terms-of-service checkbox could not be read without signing in (**unverified** whether it adds anything).

**Caching and mirroring**

- No clause in the Baseline API Terms, the Data Access Terms or the Cisco API License Terms mentions caching, storing or mirroring API responses for your own use.
- §2.1: "You (and Your end users) must not redistribute, resell, or sublicense the Cisco API(s) or access to the Cisco API(s)." ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf))
- §1: you will not "provide third parties with access to Cisco API(s) or any API Integration for use by any third party", nor "create or offer an API Integration that functions substantially similar to the Cisco API(s) and make it available to third parties", nor access the APIs "to replicate or compete with any Cisco Offer". ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf)) A local mirror for one operator's own Checks is not named; **shipping a mirror inside the tool, or sharing one between operators, would be redistribution**. Whether a per-operator local mirror is acceptable to Cisco is **unverified**; Cisco's own wording "without having to pull the entire database" suggests full pulls are expected.
- §4: Cisco may set and enforce limits "to protect security, stability, fair allocation, and service quality". The Data Access Terms add: do not "use an unreasonable amount of bandwidth or adversely impact the stability of an Access Method". ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf), [Data Access Terms §2.3(C)(5)](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Data-Access-Supplemental-Terms.pdf))
- §13: on termination, "disable and remove all Cisco-provided materials from Your systems". A mirror would have to be deletable. ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf))
- §7: data from Cisco APIs must not be used to train ML or AI models without written permission. ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf))

**Logging of inputs**

- §2.1: "Cisco may monitor Your use of the Cisco API(s) to ensure quality, improve the Cisco API(s), and verify compliance." The Data Access Terms reserve the right to "review Your … use of the Access Method". ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf), [Data Access Terms §2.3(E)(2)](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Data-Access-Supplemental-Terms.pdf))
- The API Console keeps per-key call reports ([Application registration](https://developer.cisco.com/docs/support-apis/application-registration/)), and every EoX record echoes the inputs back in `EOXInputValue`. Inputs are in the URL path or query string, which proxies and gateways commonly log.
- No Cisco page found says what Cisco logs from request inputs or how long it keeps them (**unverified**). Treat anything sent as seen and kept by Cisco.

**Credentials**

- "Credentials (e.g., passwords, keys, and client IDs) are personal to You and must be kept confidential and secure. Credential sharing is prohibited …" and "Your credentials must not be embedded in open source projects." ([Baseline API Terms §1](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf); the [Cisco API License Terms](https://developer.cisco.com/site/license/cisco-api-license) add "must be encrypted in transit")
- §11: you are "solely responsible for ensuring the security of … credentials (including, for example, client IDs or client secrets)" and must notify Cisco of a security incident that could compromise the APIs. ([Baseline API Terms](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/supplemental-terms/Baseline-API-Terms.pdf))

## What this means for the open tickets

Facts only; the decisions belong to the tickets.

- **For the Check ticket (EoX):** a whole-database pull through `EOXByDates` sends only dates, so EoX hardware Checks can match `show inventory` PIDs offline and keep to ADR 0006's "sends no device data". Release-based EoX cannot be matched offline from that pull, because records carry no release field. Page size, record count and rate limits must be measured with a real key.
- **For the Check ticket (Cisco Suggested release):** keeping device data on the PC means sending a fixed, built-in list of base PIDs or mdfIds, not the ones found in a Run. The coverage of that list is unknown until tested with a key.
- **For [How Cisco API keys are supplied and kept](https://github.com/b-git-hub/network-analyser/issues/77):** the Client Secret never expires, is emailed at registration, must be sent to `id.cisco.com` to get a token, and must be kept confidential under Cisco's terms. Because ADR 0006 keeps the tool offline while a secret is held, using this key means the tool is online while holding *this* secret; the ticket has to decide how that fits. A time-boxed API Developer role and a dedicated app with only EoX and Software Suggestion ticked are the least-privilege options Cisco offers.
