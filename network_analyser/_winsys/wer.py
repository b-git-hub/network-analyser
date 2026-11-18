"""Windows Error Reporting: switch it off for this process, and read machine settings.

Decision #6, point 9: `SetErrorMode(SEM_NOGPFAULTERRORBOX)` stops Windows Error Reporting for
the process with no registry write (so never `WerAddExcludedApplication`, which writes one).
The registry is opened with `KEY_READ` only: this module reads HKLM keys and never creates,
sets or deletes anything (tests/arch/test_registry_read_only.py). What the keys mean is
decided by the caller, `cli.crash_dump_guard`, so it can be tested on any OS with a fake.
"""

import sys
from collections.abc import Mapping
from enum import Enum, unique

SEM_NOGPFAULTERRORBOX = 0x0002


@unique
class RegistryView(Enum):
    """Which view of the HKLM SOFTWARE keys to read: 64-bit and 32-bit programs differ."""

    BIT64 = "64-bit"
    BIT32 = "32-bit"


class RegistryUnreadableError(Exception):
    """A registry key exists but could not be read, or there is no Windows registry here."""

    def __init__(self) -> None:
        """Carry a fixed message only: the OS error's text is never kept."""
        super().__init__("a registry key could not be read")


if sys.platform == "win32":
    import ctypes
    import winreg

    _VIEW_ACCESS = {
        RegistryView.BIT64: winreg.KEY_WOW64_64KEY,
        RegistryView.BIT32: winreg.KEY_WOW64_32KEY,
    }

    def suppress_error_reporting() -> None:
        """Stop Windows Error Reporting for this process, keeping the other error-mode flags."""
        kernel32 = ctypes.windll.kernel32
        kernel32.SetErrorMode(kernel32.GetErrorMode() | SEM_NOGPFAULTERRORBOX)

    def read_machine_key(path: str, view: RegistryView) -> Mapping[str, object] | None:
        """Return the values of the HKLM key at `path` by name, or None if it does not exist.

        Raises:
            RegistryUnreadableError: the key exists but could not be read.
        """
        access = winreg.KEY_READ | _VIEW_ACCESS[view]
        try:
            with winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
                _subkeys, value_count, _modified = winreg.QueryInfoKey(key)
                values: dict[str, object] = {}
                for index in range(value_count):
                    name, value, _kind = winreg.EnumValue(key, index)
                    values[name] = value
                return values
        except FileNotFoundError:
            return None
        except OSError as error:
            raise RegistryUnreadableError from error

else:

    def suppress_error_reporting() -> None:
        """Do nothing: there is no Windows Error Reporting here."""

    def read_machine_key(path: str, view: RegistryView) -> Mapping[str, object] | None:
        """Say the key cannot be read: there is no Windows registry here.

        Raises:
            RegistryUnreadableError: always, so the caller fails closed.
        """
        del path, view
        raise RegistryUnreadableError
