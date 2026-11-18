"""Parse command output with the ntc-templates TextFSM templates (decision #2).

The templates are read from the copy bundled with the tool, never from a folder named by
an environment variable. A parser problem is never fatal: it gives None, and the caller
records the data as unknown with a fixed reason (#30 section 8). The output itself is never
kept or shown.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Final

import ntc_templates
from ntc_templates.parse import parse_output

_TEMPLATES: Final = str(Path(ntc_templates.__file__).parent / "templates")


def parse(template_platform: str, command: str, text: str) -> list[Mapping[str, object]] | None:
    """Return the rows the ntc-templates template for `command` reads, or None on failure."""
    try:
        rows = parse_output(
            platform=template_platform, command=command, data=text, template_dir=_TEMPLATES
        )
    except Exception:  # noqa: BLE001 (any parser failure leaves the data unknown, #30)
        return None
    if not isinstance(rows, list):
        return None
    return [row for row in rows if isinstance(row, dict)]
