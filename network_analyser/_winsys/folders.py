"""What Windows says about a folder: its drive kind, sync roots, and who may modify it.

Used by the Run folder checks (#42, stories 120-121; decided on #26). Every function here
only reads: none changes a permission, a registry value or a file. On other systems each
says it cannot tell (UNKNOWN, no sync roots, None), so tests inject answers instead.
"""

import sys
from dataclasses import dataclass
from enum import Enum


class DriveKind(Enum):
    """The kind of drive a folder sits on."""

    LOCAL = "local"
    NETWORK = "network"
    REMOVABLE = "removable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Grant:
    """An account that an allow entry in a folder's permissions lets modify it."""

    sid: str
    """The account's SID, e.g. `S-1-5-18`."""
    name: str
    r"""Its name as Windows shows it, e.g. `NT AUTHORITY\SYSTEM`, or the SID if unknown."""


EVERYONE_SID = "S-1-1-0"

if sys.platform == "win32":
    import ctypes
    import winreg
    from ctypes import wintypes
    from pathlib import PureWindowsPath

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetDriveTypeW.restype = wintypes.UINT
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,  # SE_OBJECT_TYPE
        wintypes.DWORD,  # SECURITY_INFORMATION
        ctypes.POINTER(ctypes.c_void_p),  # owner
        ctypes.POINTER(ctypes.c_void_p),  # group
        ctypes.POINTER(ctypes.c_void_p),  # DACL
        ctypes.POINTER(ctypes.c_void_p),  # SACL
        ctypes.POINTER(ctypes.c_void_p),  # security descriptor
    ]
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_int),
    ]
    _advapi32.LookupAccountSidW.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,  # TOKEN_INFORMATION_CLASS
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL

    class _Acl(ctypes.Structure):
        _fields_ = (
            ("AclRevision", wintypes.BYTE),
            ("Sbz1", wintypes.BYTE),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        )

    class _AccessAllowedAce(ctypes.Structure):
        # ACE_HEADER, then the access mask; the SID starts where SidStart is.
        _fields_ = (
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        )

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = (("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD))

    _DRIVE_KINDS = {
        2: DriveKind.REMOVABLE,  # DRIVE_REMOVABLE
        3: DriveKind.LOCAL,  # DRIVE_FIXED
        4: DriveKind.NETWORK,  # DRIVE_REMOTE (mapped drives too)
        5: DriveKind.REMOVABLE,  # DRIVE_CDROM
        6: DriveKind.LOCAL,  # DRIVE_RAMDISK
    }
    _SE_FILE_OBJECT = 1
    _DACL_SECURITY_INFORMATION = 0x4
    _ACCESS_ALLOWED_ACE_TYPES = frozenset({0x0, 0x9})  # plain and callback allow entries
    # Rights that let an account change what is in the folder or its permissions: add files
    # or folders, delete, change the DACL or owner, and the generic write and all rights.
    _MODIFY_RIGHTS = (
        0x2  # FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x4  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x40  # FILE_DELETE_CHILD
        | 0x10000  # DELETE
        | 0x40000  # WRITE_DAC
        | 0x80000  # WRITE_OWNER
        | 0x10000000  # GENERIC_ALL
        | 0x40000000  # GENERIC_WRITE
    )
    _TOKEN_QUERY = 0x8
    _TOKEN_USER = 1
    _ONEDRIVE_ACCOUNTS = r"Software\Microsoft\OneDrive\Accounts"
    _SYNC_ROOT_MANAGER = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager"

    def _plain(path: str) -> str:
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        if path.startswith("\\\\?\\"):
            return path[4:]
        return path

    def drive_kind(path: str) -> DriveKind:
        """Say whether `path` is on a local, network (UNC or mapped) or removable drive."""
        plain = _plain(path)
        if plain.startswith("\\\\"):
            return DriveKind.NETWORK
        anchor = PureWindowsPath(plain).anchor
        if not anchor:
            return DriveKind.UNKNOWN
        return _DRIVE_KINDS.get(_kernel32.GetDriveTypeW(anchor), DriveKind.UNKNOWN)

    def _subkeys(root: int, path: str) -> list[str]:
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[0]
                return [winreg.EnumKey(key, i) for i in range(count)]
        except OSError:
            return []

    def _values(root: int, path: str) -> list[tuple[str, object]]:
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                return [winreg.EnumValue(key, i)[:2] for i in range(count)]
        except OSError:
            return []

    def sync_roots() -> tuple[str, ...]:
        """Return the folders a cloud service syncs for this user, best-effort.

        Reads, never writes: OneDrive's account folders, and every sync root registered
        with Windows (the Cloud Files API that OneDrive, Dropbox and others use).
        """
        roots: list[str] = []
        for account in _subkeys(winreg.HKEY_CURRENT_USER, _ONEDRIVE_ACCOUNTS):
            for name, data in _values(winreg.HKEY_CURRENT_USER, rf"{_ONEDRIVE_ACCOUNTS}\{account}"):
                if name == "UserFolder" and isinstance(data, str) and data:
                    roots.append(data)
        user = current_user_sid()
        for provider in _subkeys(winreg.HKEY_LOCAL_MACHINE, _SYNC_ROOT_MANAGER):
            for sid, data in _values(
                winreg.HKEY_LOCAL_MACHINE, rf"{_SYNC_ROOT_MANAGER}\{provider}\UserSyncRoots"
            ):
                if (user is None or sid == user) and isinstance(data, str) and data:
                    roots.append(data)
        return tuple(roots)

    def _sid_string(sid: int | None) -> str | None:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def _account_name(sid: int | None, fallback: str) -> str:
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_size = wintypes.DWORD(len(name))
        domain_size = wintypes.DWORD(len(domain))
        use = ctypes.c_int()
        found = _advapi32.LookupAccountSidW(
            None,
            sid,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        if not found:
            return fallback
        return f"{domain.value}\\{name.value}" if domain.value else name.value

    def modify_grants(path: str) -> tuple[Grant, ...] | None:
        """Return the accounts the folder's allow entries let modify it, or None if unread.

        Entries that apply only to what is created inside the folder count too, because
        they let an account change the files a Run writes there. Deny entries are ignored,
        so the answer errs towards warning.
        """
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        status = _advapi32.GetNamedSecurityInfoW(
            path,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if status != 0:
            return None
        try:
            if not dacl.value:  # a NULL DACL lets everyone do everything
                return (Grant(sid=EVERYONE_SID, name="Everyone"),)
            acl = _Acl.from_address(dacl.value)
            grants: list[Grant] = []
            for index in range(acl.AceCount):
                ace_pointer = ctypes.c_void_p()
                if not _advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                    return None
                if ace_pointer.value is None:
                    return None
                ace = _AccessAllowedAce.from_address(ace_pointer.value)
                if ace.AceType not in _ACCESS_ALLOWED_ACE_TYPES:
                    continue
                if not ace.Mask & _MODIFY_RIGHTS:
                    continue
                sid = ace_pointer.value + _AccessAllowedAce.SidStart.offset
                text = _sid_string(sid)
                if text is None:
                    return None
                grants.append(Grant(sid=text, name=_account_name(sid, text)))
            return tuple(grants)
        finally:
            _kernel32.LocalFree(descriptor)

    def current_user_sid() -> str | None:
        """Return the SID of the account this process runs as, or None if unread."""
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            return None
        try:
            size = wintypes.DWORD()
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            if not size.value:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not _advapi32.GetTokenInformation(
                token, _TOKEN_USER, buffer, size, ctypes.byref(size)
            ):
                return None
            user = _SidAndAttributes.from_buffer(buffer)
            return _sid_string(user.Sid)
        finally:
            _kernel32.CloseHandle(token)

else:

    def drive_kind(path: str) -> DriveKind:  # noqa: ARG001 (same signature as on Windows)
        """Say UNKNOWN: drive kinds are a Windows question."""
        return DriveKind.UNKNOWN

    def sync_roots() -> tuple[str, ...]:
        """Say none: sync roots are registered with Windows."""
        return ()

    def modify_grants(path: str) -> tuple[Grant, ...] | None:  # noqa: ARG001 (as on Windows)
        """Say None (cannot tell): the permissions read is written for Windows only."""
        return None

    def current_user_sid() -> str | None:
        """Say None: SIDs are a Windows idea."""
        return None
