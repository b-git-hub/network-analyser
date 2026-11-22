"""The one scanned writer for the Run folder's plaintext files (#48 follow-up; #52).

`topology.json` (#52), `diagram.html`, `diagram.drawio` (#63, #65) and `run-report.html`
(#66) are written here and nowhere else. `topology` and `diagram` may import only `records`,
so they hand their text or data to the cli, which writes it through this module. The Run
report is assembled in the cli and written by `run_output.report` through the same function,
with the Run's `SecretScan`:

- every piece of text passes through the scan, and a match is written as `[blocked]` (the
  Run carries on and warns once at the end, story 164);
- the file is written to a temporary file in the Run folder, flushed to disk, then renamed
  over the name, so it is either whole or not there.

Escaping can hide a secret from a scan of the finished text: JSON puts a backslash before a
quote, and HTML writes `<` as `&lt;`. So `write_scanned_json` scans every string, keys
included, before encoding, then the whole text again. A writer of HTML or XML must likewise
scan each value before escaping it (`SecretScan.contains_secret`), then write the page with
`write_scanned_text`.
"""

import json
import os
import secrets
from pathlib import Path

from network_analyser._winsys import retry_rename
from network_analyser.credentials import SecretScan
from network_analyser.records.safe_names import safe_name_problem
from network_analyser.run_output.folder import RunFolder

_NAME_MAX = 64


def write_scanned_text(folder: RunFolder, name: str, text: str, scan: SecretScan) -> int:
    """Write `text` as `name` in the Run folder, secrets blocked; return the scan's hits.

    Raises:
        ValueError: `name` is not a plain file name (letters, digits, `-`, `.`, `_`).
        OSError: the file could not be written. A temporary file may be left behind if
            the disk fails mid-write; like the file, it never holds a secret.
    """
    if safe_name_problem(name, _NAME_MAX) is not None:
        msg = "not a plain file name"
        raise ValueError(msg)
    redacted, hits = scan.contains_secret(text)
    path = Path(folder.io_path) / name
    temporary = path.with_name(f"{name}.tmp-{secrets.token_hex(8)}")
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(handle, redacted.encode("utf-8"))
        os.fsync(handle)
    finally:
        os.close(handle)
    retry_rename(lambda: temporary.replace(path))
    return hits


def write_scanned_json(folder: RunFolder, name: str, data: object, scan: SecretScan) -> int:
    """Write `data` as indented UTF-8 JSON, every string scanned first; return the hits.

    `data` is plain JSON data: dicts, lists, str, int, float, bool and None.

    Raises:
        TypeError: `data` holds something JSON cannot hold.
        ValueError, OSError: as `write_scanned_text`.
    """
    hits = 0

    def redact(text: str) -> str:
        nonlocal hits
        redacted, found = scan.contains_secret(text)
        hits += found
        return redacted

    def walk(value: object) -> object:
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {redact(key): walk(item) for key, item in value.items()}
        return value

    text = json.dumps(walk(data), ensure_ascii=False, indent=1) + "\n"
    return hits + write_scanned_text(folder, name, text, scan)
