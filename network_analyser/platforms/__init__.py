"""The `platforms` module: what the tool knows about each supported Platform.

One subpackage per Platform (`ios_xe`, `nxos`), built in: identification patterns, the
compiled-in command allow-list, parsers from command output to plain records, the
Backup acceptance check and role-snippet generation (ADR 0005). Nothing is loaded from
a plugins folder. Calls no other module.
"""
