"""The end-of-Run summary of the Credential Sets (#54; stories 36, 88, 158).

Built straight from a `CrawlResult`: each set's successes, failures and retirement, a next
step for each Retired Credential Set, and the notice shown the moment a set is retired.
Usernames are typed by the operator but still escaped before they are printed.
"""

from network_analyser.cli import run_summary
from network_analyser.records import CredentialSetResult, CredentialSetView, Platform
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.events import CredentialSetRetired


def _result(*sets: CredentialSetResult) -> CrawlResult:
    return CrawlResult(devices=(), credential_sets=sets)


def test_each_sets_results_are_listed_in_order() -> None:
    result = _result(
        CredentialSetResult(CredentialSetView(1, "netops-ro", None), 4, 0, retired=False),
        CredentialSetResult(CredentialSetView(2, "svc-nx", Platform.NX_OS), 0, 3, retired=True),
    )

    shown = run_summary.summary(result)

    assert (
        "Credential Sets:\n"
        "  Set 1 (netops-ro): 4 worked, 0 failed\n"
        "  Set 2 (svc-nx, NX-OS only): 0 worked, 3 failed, retired"
    ) in shown


def test_a_retired_set_needs_attention_with_its_next_step() -> None:
    result = _result(
        CredentialSetResult(CredentialSetView(1, "netops-ro", None), 4, 0, retired=False),
        CredentialSetResult(CredentialSetView(2, "svc-nx", None), 0, 3, retired=True),
    )

    shown = run_summary.summary(result)

    assert run_summary.needs_attention(result)
    assert (
        "Credential Set 2 (svc-nx) was retired after 3 failed logins. A mistyped password is "
        "the usual cause: check the password and each device's AAA lockout counter, then run "
        "again."
    ) in shown


def test_sets_that_were_never_retired_need_no_attention() -> None:
    result = _result(
        CredentialSetResult(CredentialSetView(1, "netops-ro", None), 4, 1, retired=False)
    )

    assert not run_summary.needs_attention(result)


def test_the_retirement_notice_names_the_set_and_escapes_its_username() -> None:
    notice = run_summary.retirement_notice(CredentialSetRetired(3, "ops\x1b[2J", 2))

    assert notice == (
        "Credential Set 3 (ops\\x1b[2J) is retired after 2 failed logins and will not be "
        "tried again this Run. A mistyped password is the usual cause."
    )
