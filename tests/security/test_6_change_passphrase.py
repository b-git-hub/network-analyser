"""Security test 6, `change-passphrase` writes no plaintext (spec #37, Testing Decisions; #58).

Run against a temporary per-user folder and a Run folder holding a canary config (an
`enable secret 9` line), `change-passphrase` leaves no plaintext on disk: not at the end, and
not at any moment on the way. Every byte the tool hands to the operating system for a file
is watched as it goes, so even a temporary file that is later renamed or removed would be
caught. The first test locks with real age, end to end. The second cuts the power at every
single file write or rename in turn, with the fast fake age, and checks that each Backup is
then wholly old or wholly new, that no plaintext is on disk, and that a rerun finishes the
change.
"""

import io
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pyrage
import pytest

from network_analyser import backup_store, run_output
from network_analyser.backup_store import ChangeStage, PassphraseFiles
from network_analyser.cli import main
from network_analyser.credentials import Secret
from tests.support import fake_age
from tests.support.run_driver import typed
from tests.support.run_folders import CONFIG, CONFIG_CANARY, make_run_folder

pytestmark = pytest.mark.security

OLD = "CANARY-pp-0ld6-current"
NEW = "CANARY-pp-n3w6-rotated"
_PLAINTEXT = (CONFIG_CANARY.encode(), b"enable secret 9", b"hostname sw-a")


class _PowerCut(BaseException):
    """The PC lost power: nothing after this point runs, not even `finally` blocks' writes."""


def _data() -> run_output.DataFolder:
    return run_output.locate_data_folder(Path(os.environ["LOCALAPPDATA"]))


def _files(data: run_output.DataFolder) -> PassphraseFiles:
    return PassphraseFiles(data.check_file, data.previous_check_file, data.change_pending)


def _plaintext_on_disk(*roots: Path) -> list[str]:
    return [
        str(path)
        for root in roots
        for path in root.rglob("*")
        if path.is_file() and any(p in path.read_bytes() for p in _PLAINTEXT)
    ]


@contextmanager
def _watched_writes(
    monkeypatch: pytest.MonkeyPatch, cut_at: int | None = None
) -> Iterator[list[bytes]]:
    """Record every `os.write`; optionally cut the power at the `cut_at`th write or rename."""
    written: list[bytes] = []
    events: list[int] = []
    real_write, real_replace = os.write, os.replace

    def event() -> None:
        events.append(1)
        if cut_at is not None and len(events) == cut_at:
            raise _PowerCut

    def write(handle: int, data: bytes | memoryview, /) -> int:
        written.append(bytes(data))
        event()
        return real_write(handle, data)

    def replace(source: str | Path, target: str | Path) -> None:
        event()
        real_replace(source, target)

    with monkeypatch.context() as patch:
        patch.setattr(os, "write", write)
        patch.setattr(os, "replace", replace)
        yield written


def _change(monkeypatch: pytest.MonkeyPatch, answers: str) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(answers))
    return main(["change-passphrase"])


def test_a_real_age_change_never_writes_the_config_in_the_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _data()
    old = backup_store.create_check_file(data.check_file, Secret(OLD))
    folder = make_run_folder(
        tmp_path / "runs" / "20261118T101530Z", old, "sw-a", register=data.run_register
    )
    backup = folder / "backups" / "sw-a__TEST0001.cfg.age"
    assert _plaintext_on_disk(data.root, folder) == []

    with _watched_writes(monkeypatch) as written:
        code = _change(monkeypatch, typed("YES", OLD, NEW, NEW, "y"))

    assert code == 0, capsys.readouterr().err
    assert pyrage.passphrase.decrypt(backup.read_bytes(), NEW) == CONFIG.encode()
    assert written  # the change did write: ciphertext, the marker and the record
    assert [w for w in written if any(p in w for p in _PLAINTEXT)] == []
    assert _plaintext_on_disk(data.root, folder) == []


def _resume(monkeypatch: pytest.MonkeyPatch, files: PassphraseFiles) -> int:
    """Run `change-passphrase` again after a power cut, answering as the operator would."""
    try:
        stage = backup_store.change_status(files).stage
    except backup_store.CheckFileError:
        pytest.fail("a power cut left no usable check file")
    if stage is ChangeStage.SWITCHED:
        return _change(monkeypatch, typed("YES", OLD, NEW, "y"))
    return _change(monkeypatch, typed("YES", OLD, NEW, NEW, "y"))


def _opens(path: Path) -> Callable[[str], bytes | None]:
    return lambda passphrase: fake_age.unlock(path.read_bytes(), passphrase)


def test_a_power_cut_at_any_write_leaves_no_plaintext_and_each_file_old_or_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_age.use_fake_age(monkeypatch)
    cut_at = 0
    while True:
        cut_at += 1
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / f"cut-{cut_at}" / "LocalAppData"))
        data = _data()
        old = backup_store.create_check_file(data.check_file, Secret(OLD))
        folder = make_run_folder(
            tmp_path / f"cut-{cut_at}" / "runs" / "20261118T101530Z",
            old,
            "sw-a",
            "sw-b",
            register=data.run_register,
        )
        backups = sorted((folder / "backups").glob("*.cfg.age"))
        configs = {p: fake_age.unlock(p.read_bytes(), OLD) for p in backups}

        written: list[bytes] = []
        try:
            with _watched_writes(monkeypatch, cut_at) as seen:
                written = seen
                _change(monkeypatch, typed("YES", OLD, NEW, NEW, "y"))
        except _PowerCut:
            pass
        else:
            break  # every write and rename has had its power cut
        capsys.readouterr()

        assert [w for w in written if any(p in w for p in _PLAINTEXT)] == [], cut_at
        assert _plaintext_on_disk(data.root, folder) == [], cut_at
        for path, config in configs.items():
            assert config in {_opens(path)(OLD), _opens(path)(NEW)}, (cut_at, path)

        assert _resume(monkeypatch, _files(data)) == 0, (cut_at, capsys.readouterr().err)
        for path, config in configs.items():
            assert _opens(path)(NEW) == config, (cut_at, path)
        assert _opens(folder / "backups" / "manifest.age")(NEW) is not None, cut_at
        assert not data.change_pending.exists(), cut_at
        assert _plaintext_on_disk(data.root, folder) == [], cut_at
    assert cut_at > 20
