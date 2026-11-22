# Issue #148 handoff, 2026-11-22

On 2026-11-22 the operator asked the building session to hand #148 to another agent, with a note on why it could not be solved. As of `b-git-hub/network-analyser@61a57ae` on `ticket-148-shape-check` (pushed), the ticket is still open. The findings and open questions are in the [handoff comment on #148](https://github.com/b-git-hub/network-analyser/issues/148#issuecomment-7075896505); this page adds why the work stopped and what the next agent must not repeat.

## Why it is not solved

- **Licence-suffixed PIDs (`CISCO1811/K9`, `ISR4451-X/K9`, `ISR4331/K9`, `CISCO3925/K9`) cannot be looked up in the path form.** Cisco's gateway returns HTTP 400 for an encoded `%2F`, on every path call, whatever the product. This is a bug in production `wire_pid` (`network_analyser/advisories/lookup.py`), not in the shape check.
- **The query form does not parse the PID.** A raw or encoded slash in `input1` returns an `EOXError` envelope, with the same description as a synthetic slash PID.
- **Cisco's documented `supportedHardware` form returns HTTP 500 for every slashed value tried.** That covers `CISCO1811/K9` on base `CISCO1811` and `CISCO3925/K9` on base `CISCO3925`. The 500 has the same body as an unknown synthetic PID, so it is either a catalogue miss or a refusal of the slash. The probe for Cisco's own sample pair (`CISCO2811` with `CISCO3925/K9`) was added in `61a57ae` but has not been run.
- **Base PIDs without the suffix** (`CISCO1811`, `ISR4451-X`, `ISR4331`) return an `EOXError` record from hardware EoX and `S3_INV_BASEPID` from Software Suggestion. `C9300-24T` works in both, so the failure follows the base PID.
- **Software EoX (Q1) has no working match rule yet.** Records come back, but `EOXInputValue` never equals the release sent, so echo-based matching fails.
- **The end-of-life question for the ISR and 1800-series PIDs is unresearched.** End-of-life would not explain the HTTP 400 on `%2F`.

Nothing here is a bug in the shape check itself. The open questions need either a result from the operator's key (the agent cannot type the Backup Passphrase or the `YES` crash-dump prompt, so each run is the operator's), or an answer from Cisco.

## What the next agent should do first

1. Ask the operator to run the script once for the sample pair. The command is `uv run --locked python -m scripts.cisco_shape_check --pid C9300-24T`, and the probe to read is "Cisco's documented sample pair". HTTP 200 means the documented form works and the earlier 500s were catalogue misses. HTTP 500 means Cisco refuses slashed `supportedHardware` values.
2. Open a bug for production `wire_pid`: licence-suffixed PIDs fail every path-form call with HTTP 400. This should not wait for #148.
3. Decide the Q1 match rule with the operator before writing the software EoX parser.
4. If step 1 returns HTTP 500, draft a question to Cisco DevNet support about licence-suffixed PIDs in `supportedHardware`.

## Do not repeat

- Do not treat `CISCO1811` or `CISCO3925` as a known-good base. Both return errors or 500s.
- Do not treat the compatible-list 500 for a slashed value as proof that the slash is refused. It is also what an unknown PID returns.
- Do not push or post anything without the operator's approval. The branch was pushed on 2026-11-22 at the operator's request.

## Update, 2026-11-22 (later): every compatible-list filter fails

Step 1 of "What the next agent should do first" has now been run, on 2026-11-22 by the operator, with `--pid C9300-24T`, on `ticket-148-shape-check` at `325daeb` (the `currentRelease` probe was added in `7d22524`, amended to `325daeb`). Results, by probe label:

- Documented sample pair, `CISCO2811` with `CISCO3925/K9` in `supportedHardware`: HTTP 500, unnamed 25-character code, error text 39 characters.
- Same base with a non-slashed value, `HWIC-1FE`: HTTP 500, same code, same 39-character error text.
- Same base with `pageIndex=1` added to both: HTTP 500, same as above.
- Same base with `currentRelease=15.0.24T7` (Cisco's documented sample): HTTP 500, same code, same 39-character error text.
- Unknown synthetic PID, no filter: HTTP 500, but with a 28-character error text, so Cisco answers differently.
- `C9300-24T`, no filter: HTTP 200 with suggestions (unchanged from earlier runs).

So the earlier reading (slash versus catalogue miss) is superseded. Every filter we have tried, of two kinds, fails with the same error text, and the unfiltered list works. This points at the filter parameters (or the request for this endpoint) rather than at licence-suffixed PIDs. Cisco's documentation, as read on 2026-11-22, is the only source of the parameter names and sample values we used; it has not been checked against a live response beyond these runs. The operator has not yet sent a question to Cisco DevNet support. The error text is not printed or recorded here, because the tool's rule is that no value from a reply is printed.

Superseded: the 2026-11-22 (earlier) reading that the 500s for `CISCO1811` and `CISCO3925` "were catalogue misses" if the documented sample returned 200. The sample returned 500, so that reading does not hold.

Related: [conventions](conventions.md), [index](index.md).
