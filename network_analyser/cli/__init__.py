"""The `cli` module: commands, prompts, progress, the final summary and exit codes.

`cli` is the composition root: the only module that talks to the console, and the only one
allowed to call every other module (CODING_STANDARDS.md).
"""

from network_analyser.cli.app import entry, main
from network_analyser.cli.crash import install_crash_hooks
from network_analyser.cli.exit_codes import ExitCode

__all__ = ["ExitCode", "entry", "install_crash_hooks", "main"]
