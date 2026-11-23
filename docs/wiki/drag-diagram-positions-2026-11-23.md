# Dragging diagram positions (2026-11-23)

On 2026-11-23 the operator decided, for [#73](https://github.com/b-git-hub/network-analyser/issues/73), that positions dragged in `diagram.html` are **saved in the browser**: `localStorage` under `network-analyser.diagram.layout.v1:` plus the page's `location.pathname`. A **Reset layout** control returns to the generated positions. Rejected for now: session-only positions (lost on every reload) and an exported positions file (one more file for the operator to manage).

Built on branch `ticket/73-drag-positions` from `b-git-hub/network-analyser@6a9d4f7`, delivered as a draft PR to `main` (see #73). As of `b-git-hub/network-analyser@72ee926`:

- every `.node` can be dragged — Visited Device, Unvisited Device, Shared Segment and Subnet; edges and area labels cannot;
- positions live in the page's existing `POS`/`SPOS` maps, so Physical, Routing, VLAN and the Findings tab keep the same place (story 144);
- one flat `id -> [x, y]` map is stored, only for ids the page places, rounded to one decimal; no device text and no network use, so the CSP and the secret scan are unchanged;
- a storage failure (disabled, private mode, quota) leaves dragging working for that viewing, silently.

Consequences, recorded deliberately:

- a copied or renamed `diagram.html` starts from the generated layout, because the key names the file's path;
- clearing the browser's site data restores the generated layout;
- a new Run folder is a new file and starts from the generated layout;
- `render` on the same folder keeps the operator's saved positions;
- `diagram.drawio`, `topology.json` and the Python layout are untouched.

Verification gap and what was done: the repo has no JavaScript test runner, so pytest pins only static contracts (key prefix, reset control, hint, CSP hash). On 2026-11-23 the implementer and the coordinator used a throwaway headless Edge harness (`playwright-core`, `channel: 'msedge'`) to drag a device, a Shared Segment and a Subnet, check live follow and edge paths, reload, Reset, a second path, malformed saved values and disabled storage; all passed, and `file://` `localStorage` works in Edge. The lab checklist row G18 repeats the check in Edge and one other installed browser. A committed browser-test harness is a candidate follow-up, not part of this change.

On the same day the full Windows suite in the worktree was `3224 passed, 21 failed, 1 skipped`; a pristine `origin/main` copy at `6a9d4f7` gave the identical 21 failures (`3220 passed`), all in trust-folder permissions, `ssh`, and zip-sum tests. The four extra passes are the new tests.
