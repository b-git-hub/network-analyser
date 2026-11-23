# #129 review-fix closeout, 2026-11-23

State of the two open children of [#129](https://github.com/b-git-hub/network-analyser/issues/129)
on 2026-11-23. Claims about code are true at
`b-git-hub/network-analyser@6a9d4f7` (`main` after PR #197) and, for #165, at
`ticket-165-software-eox-match@4bc30ba` (PR #198, open, not merged by this session).

## What was open

On 2026-11-23, [#142](https://github.com/b-git-hub/network-analyser/issues/142) and
[#165](https://github.com/b-git-hub/network-analyser/issues/165) were the only open children.
[#192](https://github.com/b-git-hub/network-analyser/issues/192) and
[#193](https://github.com/b-git-hub/network-analyser/issues/193) are follow-ups, not children.
The parent still waits on the operator's merge, tag, GitHub Release and `build.ps1`, as recorded
on [the 2026-11-22 status page](review-fixes-status-2026-11-22.md).

## #165: software EoX match rule and NX-OS OSType

Decided by the operator on 2026-11-23; the code is in PR #198.

- **The echo is not an ownership key.** Cisco's EoX API reference shows the query form's
  `EOXInputValue` as `input1=12.4%2815%29T,IOS`
  ([EoX API reference](https://developer.cisco.com/docs/support-apis/eox), `EOXRecordType` →
  `EOXInputValue`). The real-release probe recorded on #164 on 2026-11-22 put the release sent
  inside `EOXInputValue`, 25 characters before and 4 after it, never equal to it. An exact
  match was already disproved; a substring match was refused because it could attach one
  release's EoX to another.
- **Rule: one release per call.** Each software EoX call carries exactly one release,
  `EOXBySWReleaseString/<page>?input1=<release>,<OSType>`. Every record and every unanswered
  entry in that reply belongs to the release asked, so `advisories` stamps both with it and
  `analysis` matches by that stamp alone. The 20-input cap is never reached; hardware EoX keeps
  its 20-PID batches. A 200 reply with no record is now silence (no EoX); an explicit refusal
  keeps its reason and still reads "could not check".
- **NX-OS `OSType` is `NX-OS`**, taken from the same API reference's `SWReleaseStringType`,
  which lists `NX-OS` beside `IOS` and `IOS-XE`. The fail-closed "no OSType name" guard remains
  for a future family added without a name.

## #142: code complete, lab checks outstanding

- Every code and documentation item from the ticket landed at `eb134b8` on 2026-11-22 and is
  recorded on [the status page](review-fixes-status-2026-11-22.md#partly-delivered-still-open).
- An audit against `main@6a9d4f7` on 2026-11-23 found **no missing code or doc item**. Two
  cosmetic items remain: `platforms/collection.py:66` defines an unused
  `DEVICE_ROLE_OUT_OF_DATE` constant whose docstring is stale, and `docs/config-facts.md`'s
  `hardening-snmp-v3-priv` row does not repeat that IOS/IOS-XE read users from `show snmp user`.
- **Lab checks K5, K7, L1 and L7 remain** ([lab checklist](../lab-checklist.md)). The operator
  said on 2026-11-23 that they have not been run yet, so #142 stays open.

## Gate at PR #198

`uv run --locked python scripts/check.py` on `ticket-165-software-eox-match@4bc30ba`:
ruff format, ruff lint and both mypy runs pass; pytest **21 failed, 3223 passed, 1 skipped**,
exactly the known Windows node ids in the
[gate baseline](review-fixes-gate-baseline-2026-11-22.md). Focused EoX and security run: 78
passed. Security marker before the final docstring commit: 250 passed, 2995 deselected.

Direct `pytest` still crashes at session finish on the shared `pytest-current` link on this PC
(2026-11-23); `scripts/check.py` and `--basetemp=<dir>` both avoid it. That is
[#193](https://github.com/b-git-hub/network-analyser/issues/193), unchanged.

## Links

- [#165](https://github.com/b-git-hub/network-analyser/issues/165) and PR #198
- [#142](https://github.com/b-git-hub/network-analyser/issues/142)
- [#129 status, 2026-11-22](review-fixes-status-2026-11-22.md) (superseded for #142/#165 by this page)
- [Gate baseline, 2026-11-22](review-fixes-gate-baseline-2026-11-22.md)
