# Operator wants a CML-testable build without being asked again

On 2026-11-18, while spec #37 was being built, the operator went AFK and said: "Nothing should stop you getting a build to me ... I need a prototype that I can test in CML, ensure the job is completed."

What the coordinating session took this to mean (2026-11-18):
- Keep the ticket frontier moving without waiting for the operator; make reversible calls and record them here rather than asking.
- The deliverable is a Windows build the operator can download and run against the CML lab from #39. A tag-triggered release (#47) needs a tag push, which the building session may not do, so CI should also build the one-folder zip on `windows-latest` and upload it as an Actions artifact on every push to the integration branch (planned with #44/#47).
- Security rules in CLAUDE.md still win over speed; anything that would trade them away waits for the operator.

See [implementing-spec-37](implementing-spec-37.md).
