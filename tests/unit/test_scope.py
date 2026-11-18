"""The Scope, the hard fence: driven through the `scope` module's public interface."""

from ipaddress import IPv4Address, IPv6Address

import pytest

from network_analyser import scope
from network_analyser.records import Placement, ScopeRecord
from network_analyser.scope import Refusal, ScopeRefused


def _scope(entries: list[str], exclusions: list[str] | None = None) -> ScopeRecord:
    result = scope.parse(entries, exclusions or [])
    assert isinstance(result, ScopeRecord), result
    return result


def _refused(entries: list[str], exclusions: list[str] | None = None) -> list[Refusal]:
    result = scope.parse(entries, exclusions or [])
    assert isinstance(result, ScopeRefused), result
    return list(result.refusals)


def ip(text: str) -> IPv4Address:
    return IPv4Address(text)


# -- accepted forms (story 7) ------------------------------------------------------------


def test_a_cidr_scope_contains_its_addresses_and_nothing_else() -> None:
    fence = _scope(["192.0.2.0/24"])

    assert fence.contains(ip("192.0.2.1"))
    assert fence.contains(ip("192.0.2.254"))
    assert not fence.contains(ip("198.51.100.1"))


def test_an_a_b_range_is_inclusive_at_both_ends() -> None:
    fence = _scope(["198.51.100.10-198.51.100.20"])

    assert fence.contains(ip("198.51.100.10"))
    assert fence.contains(ip("198.51.100.20"))
    assert not fence.contains(ip("198.51.100.9"))
    assert not fence.contains(ip("198.51.100.21"))
    assert fence.address_count == 11


def test_a_single_address_is_a_scope_of_one() -> None:
    fence = _scope(["203.0.113.7"])

    assert fence.contains(ip("203.0.113.7"))
    assert not fence.contains(ip("203.0.113.8"))
    assert fence.address_count == 1


def test_entries_may_carry_surrounding_spaces() -> None:
    fence = _scope([" 198.51.100.10 - 198.51.100.12 "])

    assert fence.address_count == 3


@pytest.mark.parametrize(
    "exclusion",
    ["192.0.2.128/25", "192.0.2.128-192.0.2.255", "192.0.2.200"],
    ids=["cidr", "range", "single"],
)
def test_an_exclusion_in_any_form_takes_its_addresses_out(exclusion: str) -> None:
    fence = _scope(["192.0.2.0/24"], [exclusion])

    assert not fence.contains(ip("192.0.2.200"))
    assert fence.placement(ip("192.0.2.200")) is Placement.EXCLUDED
    assert fence.contains(ip("192.0.2.10"))


def test_the_address_count_leaves_out_excluded_addresses() -> None:
    fence = _scope(["192.0.2.0/24", "198.51.100.0/24"], ["192.0.2.128/25", "198.51.100.5"])

    assert fence.address_count == 256 + 256 - 128 - 1


def test_an_exclusion_reaching_past_the_scope_counts_only_what_it_removes() -> None:
    fence = _scope(["192.0.2.0/25"], ["192.0.2.64-192.0.2.200"])

    assert fence.address_count == 64


# -- refused in full (story 8) ------------------------------------------------------------

REFUSED_ENTRIES = [
    pytest.param("192.0.2.1/24", "host bits are set (did you mean 192.0.2.0/24?)", id="host bits"),
    pytest.param("192.0.2.20-192.0.2.10", "the range is reversed", id="reversed range"),
    pytest.param("sw-a.example.net", "hostnames are refused; give an IPv4 address", id="hostname"),
    pytest.param("2001:db8::/32", "IPv6 is not supported in v1", id="ipv6"),
    pytest.param("192.0.2.300", "not an IPv4 address, a-b range or CIDR", id="bad octet"),
    pytest.param("192.0.2.0/33", "not an IPv4 address, a-b range or CIDR", id="bad prefix"),
    pytest.param("192.0.2.1-", "not an IPv4 address, a-b range or CIDR", id="half range"),
    pytest.param("", "the entry is empty", id="empty"),
]


@pytest.mark.parametrize(("entry", "reason"), REFUSED_ENTRIES)
def test_an_invalid_entry_refuses_the_whole_scope(entry: str, reason: str) -> None:
    assert _refused(["198.51.100.0/24", entry]) == [Refusal(entry, reason)]


@pytest.mark.parametrize(("entry", "reason"), REFUSED_ENTRIES)
def test_an_invalid_exclusion_refuses_the_whole_scope(entry: str, reason: str) -> None:
    assert _refused(["198.51.100.0/24"], [entry]) == [Refusal(entry, reason, exclusion=True)]


def test_an_exclusion_that_matches_nothing_refuses_the_scope() -> None:
    assert _refused(["192.0.2.0/24"], ["198.51.100.0/24"]) == [
        Refusal("198.51.100.0/24", "this exclusion matches nothing in the Scope", exclusion=True)
    ]


def test_every_bad_entry_is_named_not_only_the_first() -> None:
    refusals = _refused(["192.0.2.1/24", "203.0.113.0/24", "sw-a"], ["2001:db8::1"])

    assert [r.entry for r in refusals] == ["192.0.2.1/24", "sw-a", "2001:db8::1"]


def test_a_scope_with_no_entries_is_refused() -> None:
    assert _refused([]) == [Refusal("", "the Scope has no entries")]


def test_a_scope_whose_exclusions_remove_every_address_is_refused() -> None:
    assert _refused(["192.0.2.0/25"], ["192.0.2.0/24"]) == [
        Refusal("", "the exclusions remove every address in the Scope")
    ]


NEVER_TARGET_ENTRIES = ["127.0.0.1", "224.0.0.0/4", "0.0.0.0", "255.255.255.255"]  # noqa: S104 (refusal targets, not a bind address)


@pytest.mark.parametrize("entry", NEVER_TARGET_ENTRIES)
def test_an_entry_that_can_never_be_a_target_is_refused(entry: str) -> None:
    assert _refused([entry]) == [
        Refusal(entry, "holds no address that can be a login target (story 41)")
    ]


# -- merging (story 9) --------------------------------------------------------------------


def test_overlapping_entries_are_merged_with_a_warning() -> None:
    fence = _scope(["192.0.2.0/24", "192.0.2.10-192.0.2.20", "198.51.100.1"])

    assert [str(r) for r in fence.ranges] == ["192.0.2.0/24", "198.51.100.1"]
    assert fence.address_count == 257
    assert fence.warnings == (
        "overlapping entries 192.0.2.0/24, 192.0.2.10-192.0.2.20 were merged into 192.0.2.0/24",
    )


def test_touching_entries_are_joined_without_a_warning() -> None:
    fence = _scope(["192.0.2.0/25", "192.0.2.128/25", "198.51.100.10-198.51.100.12"])

    assert [str(r) for r in fence.ranges] == ["192.0.2.0/24", "198.51.100.10-198.51.100.12"]
    assert fence.warnings == ()


def test_the_same_entry_twice_is_an_overlap() -> None:
    fence = _scope(["203.0.113.5", "203.0.113.5"])

    assert fence.address_count == 1
    assert len(fence.warnings) == 1


def test_overlapping_exclusions_are_merged_too() -> None:
    fence = _scope(["192.0.2.0/24"], ["192.0.2.0/26", "192.0.2.32/27"])

    assert [str(r) for r in fence.exclusions] == ["192.0.2.0/26"]
    assert fence.address_count == 192
    assert len(fence.warnings) == 1


# -- contains(): the single in-Scope check (story 41) -------------------------------------


@pytest.mark.parametrize(
    "target",
    ["0.0.0.0", "0.0.0.1", "127.0.0.1", "224.0.0.5", "239.255.255.250", "255.255.255.255"],  # noqa: S104 (refusal targets)
)
def test_contains_refuses_targets_that_are_never_logged_into(target: str) -> None:
    whole_internet = _scope(["0.0.0.0/0"])

    assert not whole_internet.contains(ip(target))
    assert whole_internet.placement(ip(target)) is Placement.NEVER_A_TARGET


def test_contains_refuses_the_reserved_block() -> None:
    assert not _scope(["0.0.0.0/0"]).contains(ip("240.0.0.1"))


def test_contains_refuses_the_network_and_broadcast_address_of_a_cidr() -> None:
    fence = _scope(["192.0.2.0/24", "198.51.100.8/30"])

    assert not fence.contains(ip("192.0.2.0"))
    assert not fence.contains(ip("192.0.2.255"))
    assert not fence.contains(ip("198.51.100.8"))
    assert not fence.contains(ip("198.51.100.11"))
    assert fence.contains(ip("198.51.100.9"))
    assert fence.placement(ip("192.0.2.255")) is Placement.NEVER_A_TARGET


def test_a_31_or_32_cidr_allows_every_address() -> None:
    fence = _scope(["198.51.100.0/31", "203.0.113.9/32"])

    assert fence.contains(ip("198.51.100.0"))
    assert fence.contains(ip("198.51.100.1"))
    assert fence.contains(ip("203.0.113.9"))


def test_a_range_entry_has_no_network_or_broadcast_address() -> None:
    fence = _scope(["192.0.2.0-192.0.2.255"])

    assert fence.contains(ip("192.0.2.0"))
    assert fence.contains(ip("192.0.2.255"))


def test_contains_says_no_to_ipv6() -> None:
    assert not _scope(["192.0.2.0/24"]).contains(IPv6Address("2001:db8::1"))


def test_placement_tells_outside_from_excluded() -> None:
    fence = _scope(["192.0.2.0/24"], ["192.0.2.5"])

    assert fence.placement(ip("198.51.100.1")) is Placement.OUTSIDE
    assert fence.placement(ip("192.0.2.5")) is Placement.EXCLUDED
    assert fence.placement(ip("192.0.2.6")) is Placement.INSIDE


# -- one prompt line at a time (stories 5-6) ----------------------------------------------


def test_check_entry_accepts_a_good_line_and_names_a_bad_one() -> None:
    assert scope.check_entry("192.0.2.0/24") is None
    assert scope.check_entry("192.0.2.0/24", exclusion=True) is None
    assert scope.check_entry("192.0.2.1/24") == Refusal(
        "192.0.2.1/24", "host bits are set (did you mean 192.0.2.0/24?)"
    )
    assert scope.check_entry("sw-a", exclusion=True) == Refusal(
        "sw-a", "hostnames are refused; give an IPv4 address", exclusion=True
    )


def test_an_exclusion_line_may_name_an_address_that_is_never_a_target() -> None:
    assert scope.check_entry("127.0.0.1", exclusion=True) is None


def test_unmatched_exclusions_names_the_ones_that_match_nothing() -> None:
    unmatched = scope.unmatched_exclusions(
        ["192.0.2.0/24"], ["192.0.2.5", "198.51.100.0/24", "203.0.113.1"]
    )

    assert unmatched == ("198.51.100.0/24", "203.0.113.1")


# -- Seeds (story 10) ---------------------------------------------------------------------


def test_seeds_inside_the_scope_are_accepted_in_order_without_repeats() -> None:
    fence = _scope(["192.0.2.0/24"])

    assert scope.check_seeds(["192.0.2.2", "192.0.2.1", "192.0.2.2"], fence) == (
        ip("192.0.2.2"),
        ip("192.0.2.1"),
    )


def test_every_bad_seed_is_refused_with_its_reason() -> None:
    fence = _scope(["192.0.2.0/24"], ["192.0.2.5"])

    result = scope.check_seeds(
        ["192.0.2.1", "198.51.100.1", "192.0.2.5", "192.0.2.255", "sw-a", "192.0.2.0/24"], fence
    )

    assert result == ScopeRefused(
        (
            Refusal("198.51.100.1", "this Seed is outside the Scope", seed=True),
            Refusal("192.0.2.5", "this Seed is excluded by the operator", seed=True),
            Refusal("192.0.2.255", f"this Seed is {Placement.NEVER_A_TARGET.value}", seed=True),
            Refusal("sw-a", "hostnames are refused; give an IPv4 address", seed=True),
            Refusal("192.0.2.0/24", "a Seed is one IPv4 address", seed=True),
        )
    )


def test_no_seeds_at_all_is_refused() -> None:
    assert scope.check_seeds([], _scope(["192.0.2.0/24"])) == ScopeRefused(
        (Refusal("", "at least one Seed is needed", seed=True),)
    )
