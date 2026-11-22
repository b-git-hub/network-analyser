"""The operator's shape-check script for ticket #148 prints shapes and never a value.

The script is run by hand with the live Cisco API Key, which no test has. Here the fake Cisco
answers at the `advisories` transport seam with synthetic replies that carry `CANARY-148-...`
values everywhere a real reply carries a real one, and the tests prove none of them reaches the
summary, the console or the disk.
"""

import ast
import io
import json
import os
import re
from pathlib import Path

import pytest

from network_analyser import backup_store, run_output
from network_analyser.advisories import (
    HttpRequest,
    HttpResponse,
    Pacer,
    Transport,
    TransportFailed,
)
from network_analyser.advisories.session import Session
from network_analyser.credentials import Secret
from scripts import cisco_shape_check
from scripts.cisco_shape_check import Inputs, collect_summary
from tests.support import fake_age
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, TOKEN, FakeCisco
from tests.support.run_driver import data_folder, typed

PASS = "CANARY-pp-148-c1sco"
CANARY_PID = "CANARY-148-PID1"
CANARY_TEXT = "CANARY-148-text"
CANARY_KEY = "CANARY-148-field"
CANARY_CODE = "CANARY-148-CODE"
OPERATOR_RELEASE = "87.65.43a"
RELEASE_VALUE = "76.54.32b"
DATE_VALUE = "2031-02-03"
PLAIN_KEY = "CANARY148PID01"
"""A key that is a plain identifier: only an allow-list keeps it out of the summary."""
CODE_SHAPED_KEY = "SSA_ERR_CANARY148"
EVERY_CANARY = (
    "CANARY-148",
    PLAIN_KEY,
    CODE_SHAPED_KEY,
    CANARY_PID,
    OPERATOR_RELEASE,
    RELEASE_VALUE,
    DATE_VALUE,
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN,
    PASS,
)


def _no_wait() -> Pacer:
    return Pacer(clock=lambda: 0.0, wait=lambda _seconds: None)


def _session(fake: Transport) -> Session:
    return Session(Secret(CLIENT_ID), Secret(CLIENT_SECRET), transport=fake, pacer=_no_wait())


def _json(status: int, document: object, headers: tuple[tuple[str, str], ...] = ()) -> HttpResponse:
    return HttpResponse(status=status, headers=headers, body=json.dumps(document).encode())


def _canary_cisco() -> FakeCisco:
    """A fake Cisco whose every reply is stuffed with canary values."""
    fake = FakeCisco()
    fake.advisory_errors[("ios", "1.2.3", None)] = (400, "INVALID_IOS_VERSION")
    fake.advisory_errors[("iosxe", "1.2.3", None)] = (400, CANARY_CODE)
    fake.advisories[("ios", OPERATOR_RELEASE, None)] = [
        {"advisoryId": CANARY_TEXT, "advisoryTitle": CANARY_TEXT, "firstFixed": [RELEASE_VALUE]}
    ]
    fake.eox_release[OPERATOR_RELEASE] = {
        "EOXInputValue": f"{CANARY_TEXT}-{OPERATOR_RELEASE}",
        "EOXInputType": CANARY_TEXT,
        "LastDateOfSupport": {"value": DATE_VALUE, "dateFormat": "yyyy-MM-dd"},
        CANARY_KEY: CANARY_TEXT,
    }
    entry = {
        "releaseFormat1": RELEASE_VALUE,
        "releaseFormat2": f"Cupertino-{RELEASE_VALUE}",
        "relDispName": f"{CANARY_TEXT}-{RELEASE_VALUE}",
        "releaseDate": DATE_VALUE,
        "isSuggested": "Y",
        "platforms": [{"name": "Nexus 7700"}, {"name": CANARY_TEXT}],
        CANARY_KEY: CANARY_TEXT,
        PLAIN_KEY: {OPERATOR_RELEASE: [1, 2], CODE_SHAPED_KEY: CANARY_TEXT},
    }
    fake.suggestions[CANARY_PID] = [entry]
    fake.compatible[CANARY_PID] = [entry]
    fake.scripted.append(
        (
            "/supporttools/eox/rest/5/EOXBySWReleaseString/1?input1=",
            _json(
                200,
                {
                    "EOXRecord": [
                        {"EOXInputValue": OPERATOR_RELEASE, CANARY_KEY: CANARY_TEXT},
                        {"EOXError": {"ErrorID": CANARY_CODE, "ErrorDescription": CANARY_TEXT}},
                    ]
                },
                headers=(("X-Mashery-Error-Code", CANARY_CODE),),
            ),
        )
    )
    return fake


def _everything() -> Inputs:
    return Inputs(pid=CANARY_PID, release=OPERATOR_RELEASE)


def test_the_summary_never_holds_a_value_from_a_reply_or_an_input() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    for canary in EVERY_CANARY:
        assert canary not in summary
    assert summary.isascii()


def test_a_key_on_the_allow_list_still_prints_so_the_summary_answers_the_ticket() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    for path in (
        r"\$\.suggestions\[\]\.suggestions\[\]\.releaseFormat1: string",
        r"\$\.suggestions\[\]\.suggestions\[\]\.relDispName: string",
        r"\$\.suggestions\[\]\.suggestions\[\]\.platforms\[\]\.name: string",
        r"\$\.suggestions\[\]\.product\.basePID: string",
        r"\$\.EOXRecord\[\]\.EOXInputValue: string",
        r"\$\.PaginationResponseRecord\.LastIndex: integer",
    ):
        assert re.search(path, summary), path


def test_a_plain_identifier_key_that_is_not_on_the_allow_list_shows_only_its_length() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    assert PLAIN_KEY not in summary
    assert CODE_SHAPED_KEY not in summary
    assert f"<field name, length {len(PLAIN_KEY)}>" in summary


def test_the_summary_says_what_shapes_came_back() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    assert "INVALID_IOS_VERSION" in summary
    assert "SSA_ERR_026" in summary
    assert "<unrecognised code, length 15>" in summary
    assert "releaseFormat1" in summary
    assert "EOXRecord" in summary
    assert "HTTP 200" in summary
    assert "HTTP 400" in summary
    assert "Nexus 7700" in summary


def test_a_field_name_that_is_not_a_plain_name_shows_only_its_length() -> None:
    fake = _canary_cisco()
    odd = {f"CANARY-148-{n}": "x" for n in range(2)}
    fake.scripted.append(("/software/suggestion/v2/suggestions/releases", _json(200, odd)))

    summary = collect_summary(_session(fake), Inputs())

    assert "CANARY-148" not in summary
    assert "<field name, length 12>" in summary


def test_an_unrecognised_error_string_shows_only_its_length() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    assert CANARY_CODE not in summary
    assert f"<unrecognised code, length {len(CANARY_CODE)}>" in summary


def test_the_licence_slash_question_reports_the_http_status_and_never_a_value() -> None:
    fake = _canary_cisco()
    fake.scripted.append(
        (
            "/software/suggestion/v2/suggestions/releases/productIds/SYNTH-PID-2%2FK9",
            _json(404, {"errorCode": CANARY_CODE, CANARY_KEY: CANARY_TEXT}),
        )
    )

    summary = collect_summary(_session(fake), Inputs())

    lines = summary.splitlines()
    label = next(
        i for i, line in enumerate(lines) if "Software Suggestion, PID with a licence slash" in line
    )
    assert "HTTP 404" in lines[label + 1]
    assert "2xx" not in summary
    assert CANARY_CODE not in summary


def test_the_operator_pid_is_also_asked_of_the_hardware_eox_path_as_the_tool_sends_it() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs(pid="SYNTH-PID-3/K9"))

    assert "/supporttools/eox/rest/5/EOXByProductID/1/SYNTH-PID-3%2FK9" in fake.paths()


def test_the_slash_pid_is_also_asked_in_the_query_form_raw_and_encoded() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs())

    paths = fake.paths()
    assert any("EOXByProductID/1?input1=SYNTH-PID-2/K9" in path for path in paths)
    assert any("EOXByProductID/1?input1=SYNTH-PID-2%2FK9" in path for path in paths)


def test_the_base_pid_without_the_licence_suffix_is_also_asked() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs(pid="SYNTH-PID-3/K9"))

    paths = fake.paths()
    assert "/supporttools/eox/rest/5/EOXByProductID/1/SYNTH-PID-3" in paths
    assert "/software/suggestion/v2/suggestions/releases/productIds/SYNTH-PID-3" in paths


def test_cisco_documented_sample_pair_is_asked_whatever_the_operator_gave() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs())

    assert any(
        path == "/software/suggestion/v2/suggestions/compatible/productId/CISCO2811"
        "?supportedHardware=CISCO3925/K9&pageIndex=1"
        for path in fake.paths()
    )


def test_cisco_documented_non_slashed_hardware_is_asked_for_comparison() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs())

    assert any(
        path == "/software/suggestion/v2/suggestions/compatible/productId/CISCO2811"
        "?supportedHardware=HWIC-1FE&pageIndex=1"
        for path in fake.paths()
    )


def test_the_suffixed_pid_is_also_asked_in_supported_hardware_as_cisco_documents_it() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs(pid="SYNTH-PID-3/K9"))

    paths = fake.paths()
    assert any(
        path.startswith("/software/suggestion/v2/suggestions/compatible/productId/SYNTH-PID-3?")
        and "supportedHardware=SYNTH-PID-3/K9" in path
        for path in paths
    )


def test_the_software_eox_is_also_asked_with_the_ios_xe_os_type() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs())

    paths = fake.paths()
    assert any("EOXBySWReleaseString/1?input1=1.2.3,IOS-XE" in path for path in paths)
    assert any("EOXBySWReleaseString/1/1.2.3,IOS-XE" in path for path in paths)


def test_the_iosxe_and_nxos_version_codes_print_by_name_when_they_match_exactly() -> None:
    fake = _canary_cisco()
    fake.advisory_errors[("iosxe", "1.2.3", None)] = (400, "INVALID_IOSXE_VERSION")
    fake.advisory_errors[("nxos", "1.2.3", "NEXUS9000")] = (400, "INVALID_NXOS_VERSION")

    summary = collect_summary(_session(fake), Inputs())

    assert "INVALID_IOSXE_VERSION x1" in summary
    assert "INVALID_NXOS_VERSION x1" in summary


def test_release_fields_report_booleans_never_the_value() -> None:
    summary = collect_summary(_session(_canary_cisco()), _everything())

    assert "releaseFormat1" in summary
    assert "dotted form" in summary
    assert "codename prefix" in summary
    assert "releaseDate" in summary
    assert "YYYY-MM-DD" in summary
    assert DATE_VALUE not in summary
    assert RELEASE_VALUE not in summary


def test_the_default_run_asks_only_about_synthetic_values() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), Inputs())

    asked = "".join(fake.paths())
    for canary in (CANARY_PID, OPERATOR_RELEASE):
        assert canary not in asked
    assert "SYNTH-PID-1" in asked
    assert "version=1.2.3" in asked


def test_the_calls_are_the_read_only_ones_the_ticket_lists() -> None:
    fake = _canary_cisco()

    collect_summary(_session(fake), _everything())

    assert fake.token_calls() == 1
    assert {request.method for request in fake.api_requests()} == {"GET"}
    assert {request.host for request in fake.requests} == {"id.cisco.com", "apix.cisco.com"}
    prefixes = (
        "/security/advisories/v2/",
        "/supporttools/eox/rest/5/",
        "/software/suggestion/v2/suggestions/",
    )
    assert all(request.path.startswith(prefixes) for request in fake.api_requests())


def test_a_request_outside_the_fence_is_refused_before_it_reaches_the_transport() -> None:
    fake = FakeCisco()
    fenced = cisco_shape_check.FencedTransport(fake)

    for host, port in (("example.com", 443), ("apix.cisco.com", 8443), ("id.cisco.com.evil", 443)):
        request = HttpRequest(host=host, port=port, method="GET", path="/x", headers=())
        with pytest.raises(cisco_shape_check.OutsideFenceError):
            fenced(request)
    assert fake.requests == []


def test_a_write_or_an_unlisted_path_is_refused_before_it_reaches_the_transport() -> None:
    fake = FakeCisco()
    fenced = cisco_shape_check.FencedTransport(fake)

    for method, host, path in (
        ("DELETE", "apix.cisco.com", "/security/advisories/v2/OSType/ios?version=1.2.3"),
        ("POST", "apix.cisco.com", "/security/advisories/v2/OSType/ios?version=1.2.3"),
        ("GET", "apix.cisco.com", "/somewhere/else"),
        ("GET", "id.cisco.com", "/oauth2/default/v1/token"),
    ):
        request = HttpRequest(host=host, port=443, method=method, path=path, headers=())
        with pytest.raises(cisco_shape_check.OutsideFenceError):
            fenced(request)
    assert fake.requests == []


def test_a_call_that_brought_no_reply_shows_fixed_text() -> None:
    fake = _canary_cisco()
    failure = TransportFailed(f"{CANARY_TEXT} came back instead of fixed text")
    fake.scripted.extend([("/security/advisories/v2/OSType/ios", failure)] * 2)  # and its retry

    summary = collect_summary(_session(fake), Inputs())

    assert CANARY_TEXT not in summary
    assert "<unrecognised reason, length " in summary


def test_a_rejected_key_is_reported_without_a_value() -> None:
    fake = FakeCisco(token_status=400, token_error="invalid_client")

    summary = collect_summary(_session(fake), _everything())

    assert "invalid_client" in summary
    assert "HTTP 400" in summary
    assert fake.api_requests() == []
    for canary in EVERY_CANARY:
        assert canary not in summary


# -- the command: the key comes from the locked file, at the passphrase prompt ---------------


@pytest.fixture(autouse=True)
def _fake_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)
    monkeypatch.setattr(cisco_shape_check, "guard_crash_dumps", lambda _ask: True)


class Operator:
    """The operator's data folder, with a check file and, when asked, a stored key."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.data: run_output.DataFolder = data_folder()
        self.monkeypatch = monkeypatch
        self.passphrase = backup_store.create_check_file(self.data.check_file, Secret(PASS))

    def store_key(self) -> None:
        from datetime import UTC, datetime  # noqa: PLC0415 (only this helper needs it)

        backup_store.lock_key_file(
            self.data.cisco_key_file,
            Secret(CLIENT_ID),
            Secret(CLIENT_SECRET),
            self.passphrase,
            set_at=datetime(2026, 11, 20, tzinfo=UTC),
        )

    def run(self, *argv: str, answers: str, fake: FakeCisco | None = None) -> tuple[int, str, str]:
        self.monkeypatch.setattr("sys.stdin", io.StringIO(answers))
        out, err = io.StringIO(), io.StringIO()
        self.monkeypatch.setattr("sys.stdout", out)
        self.monkeypatch.setattr("sys.stderr", err)
        code = cisco_shape_check.main(
            list(argv), transport=fake or _canary_cisco(), pacer=_no_wait()
        )
        return code, out.getvalue(), err.getvalue()


@pytest.fixture
def operator(monkeypatch: pytest.MonkeyPatch) -> Operator:
    return Operator(monkeypatch)


def _files_holding(root: Path, needle: str) -> list[Path]:
    found: list[Path] = []
    for folder, _dirs, names in os.walk(root):
        found.extend(
            Path(folder, name)
            for name in names
            if needle.encode() in Path(folder, name).read_bytes()
        )
    return found


def test_the_key_is_unlocked_with_the_passphrase_and_nothing_secret_is_shown_or_kept(
    operator: Operator,
) -> None:
    operator.store_key()
    fake = _canary_cisco()

    code, out, err = operator.run(
        "--pid", CANARY_PID, "--release", OPERATOR_RELEASE, answers=typed(PASS), fake=fake
    )

    assert code == 0, err
    assert fake.token_calls() == 1
    assert "Backup Passphrase" in err
    assert "INVALID_IOS_VERSION" in out
    for canary in EVERY_CANARY:
        assert canary not in out + err
    local = Path(os.environ["LOCALAPPDATA"])
    for canary in (CLIENT_ID, CLIENT_SECRET, TOKEN, PASS):
        assert _files_holding(local, canary) == []
        assert _files_holding(Path.cwd(), canary) == []


def test_the_operator_values_are_in_the_secret_scan_so_a_printed_line_with_one_is_blocked(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator.store_key()
    leaky = f"a line that wrongly holds {CANARY_PID} and {OPERATOR_RELEASE}"
    monkeypatch.setattr(cisco_shape_check, "collect_summary", lambda _session, _inputs: leaky)

    code, out, err = operator.run(
        "--pid", CANARY_PID, "--release", OPERATOR_RELEASE, answers=typed(PASS)
    )

    assert code == 0, err
    assert CANARY_PID not in out + err
    assert OPERATOR_RELEASE not in out + err
    assert "[blocked]" in out


def test_a_wrong_passphrase_stops_before_anything_is_sent(operator: Operator) -> None:
    operator.store_key()
    fake = _canary_cisco()

    code, out, _err = operator.run(answers=typed("CANARY-148-wr0ng-pass") * 3, fake=fake)

    assert code == 2
    assert fake.requests == []
    assert out == ""


def test_with_no_stored_key_nothing_is_asked_or_sent(operator: Operator) -> None:
    fake = _canary_cisco()

    code, out, err = operator.run(answers="", fake=fake)

    assert code == 2
    assert fake.requests == []
    assert out == ""
    assert "cisco-key set" in err


def test_the_key_is_never_taken_from_an_option_or_the_environment(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator.store_key()
    monkeypatch.setenv("CISCO_CLIENT_SECRET", "CANARY-148-env-secret")

    code, out, err = operator.run("--client-secret", "CANARY-148-opt-secret", answers="")

    assert code == 2
    assert "CANARY-148" not in out + err


@pytest.mark.parametrize(
    "argv",
    [
        ["--pid", "CANARY-148 bad pid"],
        ["--pid", "CANARY-148/../x"],
        ["--release", "CANARY-148-release"],
        ["--release-os", "CANARY-148-os"],
        ["--proxy", "CANARY-148-proxy"],
        ["CANARY-148-stray"],
    ],
)
def test_an_odd_input_is_refused_and_never_echoed(operator: Operator, argv: list[str]) -> None:
    operator.store_key()
    fake = _canary_cisco()

    code, out, err = operator.run(*argv, answers=typed(PASS), fake=fake)

    assert code == 2
    assert fake.requests == []
    assert "CANARY-148" not in out + err
    assert "Backup Passphrase" not in err


def test_the_script_uses_no_http_client_of_its_own() -> None:
    tree = ast.parse(Path(cisco_shape_check.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert not imported & {"urllib", "requests", "http", "socket", "ssl", "truststore", "os"}
