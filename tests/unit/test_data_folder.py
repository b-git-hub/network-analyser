"""The per-user data folder, and the lock that lets one Run or change-passphrase run at once.

Spec #37 "Per-user data", story 16; decided on #26 and #22.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

from network_analyser import run_output
from tests.support.source_scan import REPO_ROOT


def test_everything_the_tool_keeps_between_runs_lives_in_one_per_user_folder(
    tmp_path: Path,
) -> None:
    data = run_output.locate_data_folder(tmp_path)

    assert data.root == tmp_path / "NetworkAnalyser"
    assert {
        "Trust Store": data.trust_store,
        "check file": data.check_file,
        "Run register": data.run_register,
        "change-pending marker": data.change_pending,
        "lock file": data.lock_file,
        "default Runs folder": data.runs,
    } == {
        "Trust Store": data.root / "trust" / "known_hosts",
        "check file": data.root / "passphrase-check.age",
        "Run register": data.root / "run-register.txt",
        "change-pending marker": data.root / "change-pending.json",
        "lock file": data.root / "instance.lock",
        "default Runs folder": data.root / "runs",
    }


def test_a_second_holder_is_refused_while_the_lock_is_held(tmp_path: Path) -> None:
    data = run_output.locate_data_folder(tmp_path)

    first = run_output.take_instance_lock(data)
    assert first is not None

    with first:
        assert run_output.take_instance_lock(data) is None


def test_the_lock_can_be_taken_again_once_released(tmp_path: Path) -> None:
    data = run_output.locate_data_folder(tmp_path)
    first = run_output.take_instance_lock(data)
    assert first is not None
    first.release()

    second = run_output.take_instance_lock(data)

    assert second is not None
    second.release()


def test_a_crashed_holder_does_not_leave_a_stale_lock(tmp_path: Path) -> None:
    data = run_output.locate_data_folder(tmp_path)
    holder = textwrap.dedent(f"""
        import sys
        from pathlib import Path
        from network_analyser import run_output
        lock = run_output.take_instance_lock(run_output.locate_data_folder(Path({str(tmp_path)!r})))
        print("held" if lock is not None else "refused", flush=True)
        sys.stdin.read()
    """)
    child = subprocess.Popen(  # noqa: S603 (our own interpreter, a fixed script)
        [sys.executable, "-c", holder],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "held"
        assert run_output.take_instance_lock(data) is None
    finally:
        child.kill()  # a crash: the holder never releases the lock itself
        child.communicate()

    after_crash = run_output.take_instance_lock(data)
    assert after_crash is not None
    after_crash.release()
