from ipaddress import IPv4Address

from network_analyser.records.events import UNEXPECTED_ERROR, ErrorRaised, error_event

CANARY = "CANARY-pw-0d44 hostname sw-a"
MESSAGES: dict[type[BaseException], str] = {
    TimeoutError: "the device did not answer in time",
    OSError: "the connection failed",
}


class _ReadTimeoutError(TimeoutError):
    pass


def test_the_nearest_type_gives_the_fixed_message_and_the_text_is_dropped() -> None:
    event = error_event(
        _ReadTimeoutError(CANARY), step="login", ip=IPv4Address("192.0.2.7"), messages=MESSAGES
    )

    assert event == ErrorRaised(
        ip=IPv4Address("192.0.2.7"),
        step="login",
        error_type="tests.unit.test_error_event._ReadTimeoutError",
        message="the device did not answer in time",
    )
    assert CANARY not in repr(event)


def test_a_type_with_no_message_gets_a_fixed_one() -> None:
    event = error_event(ValueError(CANARY), step="parse", ip=None, messages=MESSAGES)

    assert event.message == UNEXPECTED_ERROR
    assert event.error_type == "builtins.ValueError"
