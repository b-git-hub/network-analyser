"""AAA and HTTP config-fact accuracy fixes (#142, the items marked lower confidence).

Synthetic configs only, driven through `platforms.read_config_facts`. A config with nothing
in it reads no fact at all, which Analysis reports as "could not decide".
"""

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    AAA_AUTHORIZATION,
    AAA_LOGIN_FALLBACK_NONE,
    HTTP_SERVER,
    FactValue,
)


def _facts(platform: Platform, text: str) -> dict[str, FactValue]:
    return {fact.name: fact.value for fact in platforms.read_config_facts(platform, text)}


def test_an_enable_method_list_that_falls_back_to_none_is_counted() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa new-model\n"
        "aaa authentication login default group tacacs+ local\n"
        "aaa authentication enable default group tacacs+ none\n",
    )

    assert facts[AAA_LOGIN_FALLBACK_NONE] == 1


def test_login_and_enable_method_lists_with_none_are_each_counted() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa authentication login default group tacacs+ none\n"
        "aaa authentication enable default none\n",
    )

    assert facts[AAA_LOGIN_FALLBACK_NONE] == 2


def test_an_enable_method_list_without_none_is_not_counted() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa authentication enable default group tacacs+ enable\n"
        "aaa authentication ppp default if-authenticated\n",
    )

    assert facts[AAA_LOGIN_FALLBACK_NONE] == 0


def test_nxos_login_authentication_with_none_is_counted() -> None:
    facts = _facts(Platform.NX_OS, "aaa authentication login default group TACACS none\n")

    assert facts[AAA_LOGIN_FALLBACK_NONE] == 1


def test_authorization_through_a_server_group_is_central() -> None:
    facts = _facts(Platform.IOS_XE, "aaa authorization exec default group tacacs+ local\n")

    assert facts[AAA_AUTHORIZATION] is True


def test_authorization_against_the_local_database_only_is_not_central() -> None:
    for line in (
        "aaa authorization exec default local",
        "aaa authorization commands 15 default local none",
        "aaa authorization config-commands",
        "aaa authorization exec default if-authenticated",
    ):
        assert _facts(Platform.IOS_XE, f"{line}\n")[AAA_AUTHORIZATION] is False


def test_central_authorization_wins_over_a_local_only_line() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa authorization exec default local\n"
        "aaa authorization commands 15 default group tacacs+ local\n",
    )

    assert facts[AAA_AUTHORIZATION] is True


def test_an_empty_config_reads_no_aaa_or_http_fact() -> None:
    assert platforms.read_config_facts(Platform.IOS_XE, "") == ()


def test_nxapi_on_plain_http_is_an_http_server() -> None:
    facts = _facts(Platform.NX_OS, "feature nxapi\nnxapi http port 80\nnxapi https port 443\n")

    assert facts[HTTP_SERVER] is True


def test_nxapi_http_port_without_the_feature_is_not_a_server() -> None:
    facts = _facts(Platform.NX_OS, "nxapi http port 80\n")

    assert facts[HTTP_SERVER] is False


def test_nxapi_with_only_https_is_not_a_plain_http_server() -> None:
    facts = _facts(Platform.NX_OS, "feature nxapi\nnxapi https port 443\n")

    assert facts[HTTP_SERVER] is False


def test_the_existing_http_server_lines_are_still_read() -> None:
    assert _facts(Platform.IOS_XE, "ip http server\n")[HTTP_SERVER] is True
    assert _facts(Platform.NX_OS, "feature http-server\n")[HTTP_SERVER] is True
    assert _facts(Platform.IOS_XE, "ip http secure-server\n")[HTTP_SERVER] is False
