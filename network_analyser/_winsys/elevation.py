"""Whether the tool runs elevated (spec #37, story 17; decision #9)."""

import sys

if sys.platform == "win32":
    import ctypes

    def is_elevated() -> bool:
        """Say whether this process runs with admin rights."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False

else:

    def is_elevated() -> bool:
        """Say no: v1 runs only on Windows, and tests elsewhere inject the answer.

        Tests run on Linux as root, where a root check would always fire.
        """
        return False
