# Usage limits stop subagents mid-ticket

On 2026-11-18 at about 12:40 UTC, while building spec #37, the account hit its 5-hour usage limit with four Opus implementers (#41–#44) and a retro agent running. All four implementers stopped mid-ticket. The limit reset at 15:30 UTC.

- Nothing was lost: each worktree kept its uncommitted changes, and each agent was resumed with SendMessage (not restarted), carrying on from its own transcript.
- The scheduled heartbeat (a one-off `send_later` reminder) was delivered only after the session's worker restarted, about 3 hours late, so it can't be relied on to recover from a limit.
- Lesson: about five concurrent Opus agents plus the coordinator's own work used up the 5-hour budget in about an hour. Use cheaper models for mechanical roles (mergers, retros that only read transcripts), and keep implementer concurrency to what the frontier truly needs.

See [implementing-spec-37](implementing-spec-37.md).
