# Review-fixes merge log

From 2026-11-22, each merged ticket gets its own dated file here, one line per file, instead of
appending to the Log tail in
[review-fixes-0.3.1-2026-11-22](../review-fixes-0.3.1-2026-11-22.md). Appending to one shared
tail made every later ticket branch conflict on the same lines during the #129 build.

File name: `YYYY-MM-DD-<ticket>-<short-sha>.md`. Content:

```text
2026-MM-DD: merged #<n> at `<merge sha>`; gate: <pytest counts>; <one notable fact>.
```

A new file never conflicts with another ticket's merge. The older Log in the coordination page
stays as history; do not rewrite it.
