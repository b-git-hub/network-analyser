"""What a `SecretScan` holds, for the test that proves it keeps no plaintext (#145).

Python cannot erase a string, so a test cannot ask a scan what it once held. It can ask what is
reachable from the scan now: the scan must hold a fingerprint of each secret and its own key,
never a typed value. Walking the object graph is the only way to say that of the real object,
rather than of a private helper.
"""

import gc
import types

_NOT_FOLLOWED = type | types.ModuleType | types.FunctionType


def reachable_text(root: object) -> list[str]:
    """Return every string or bytes value reachable from `root`, as text.

    Classes, modules and functions are not followed: they lead to every constant in the
    process, which would make the answer meaningless.
    """
    seen: set[int] = set()
    todo: list[object] = [root]
    found: list[str] = []
    while todo:
        item = todo.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, bytes):
            found.append(item.decode("latin-1"))
        elif not isinstance(item, _NOT_FOLLOWED):
            todo.extend(gc.get_referents(item))
    return found
