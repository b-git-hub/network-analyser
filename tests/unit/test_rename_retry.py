"""The Windows rename retry: wait out the moment another process holds the file (#158).

On Windows an antivirus scanner, the search indexer or a backup agent can hold a new
temporary file open for a moment, and the rename then raises `PermissionError`. Every
temp-then-rename writer goes through `_winsys.retry_rename`, which waits on the `SLEEP` seam,
so these tests are deterministic and never really sleep.
"""

from pathlib import Path

import pytest

from network_analyser._winsys import rename


def _record_waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    waits: list[float] = []
    monkeypatch.setattr(rename, "SLEEP", waits.append)
    return waits


def test_a_rename_refused_twice_succeeds_on_the_third_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits = _record_waits(monkeypatch)
    attempts = 0

    def flaky() -> Path:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise PermissionError(13, "the process cannot access the file")
        return Path("renamed")

    rename.retry_rename(flaky)

    assert attempts == 3
    assert waits == sorted(waits)
    assert len(waits) == 2
    assert sum(waits) <= 2.0


def test_a_rename_that_is_always_refused_raises_the_last_permission_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits = _record_waits(monkeypatch)
    attempts = 0

    def refused() -> None:
        nonlocal attempts
        attempts += 1
        raise PermissionError(13, "the process cannot access the file")

    with pytest.raises(PermissionError):
        rename.retry_rename(refused)

    assert attempts == len(waits) + 1
    assert sum(waits) <= 2.0


def test_any_other_error_is_raised_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    waits = _record_waits(monkeypatch)
    attempts = 0

    def missing() -> None:
        nonlocal attempts
        attempts += 1
        raise FileNotFoundError(2, "the system cannot find the file")

    with pytest.raises(FileNotFoundError):
        rename.retry_rename(missing)

    assert attempts == 1
    assert waits == []
