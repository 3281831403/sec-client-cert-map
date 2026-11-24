"""客户端证书到账号映射的规格测试：初始 15 个红，全部由 NotImplementedError 触发。"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from certmap import (
    check_revocation,
    map_batch,
    match_rule,
    normalize_name,
    parse_cert,
    pick_rule,
    rule_score,
    subject_of,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def _rule(pattern: str, account: str | None = None) -> dict:
    rule = {"pattern": pattern}
    if account is not None:
        rule["account"] = account
    return rule


def _cert(
    cert_id: str,
    cn: str,
    *,
    org: str = "Acme",
    ou: str = "Platform",
    issuer: tuple[str, str] = ("CA-A", "Acme"),
    serial: str = "1001",
    account: str | None = None,
) -> dict:
    extensions = {}
    if account is not None:
        extensions["clientAccount"] = account
    return {
        "id": cert_id,
        "subject": {"CN": cn, "O": org, "OU": ou},
        "issuer": {"CN": issuer[0], "O": issuer[1]},
        "serial": serial,
        "extensions": extensions,
    }


def test_01_wildcard_rule_must_not_cross_dot_or_use_suffix_match():
    wildcard = _rule("CN=*.example.com", "edge")
    assert match_rule(wildcard, _cert("leaf-01a", "a.b.example.com")) is False
    assert match_rule(wildcard, _cert("leaf-01b", "badexample.com")) is False
    assert (
        match_rule(
            _rule("CN=api.*.example.com", "edge"),
            _cert("leaf-01c", "api.x.example.com"),
        )
        is False
    )
    assert match_rule(wildcard, _cert("leaf-01d", "api.example.com")) is True


def test_02_rule_score_must_distinguish_exact_from_wildcard():
    cert = _cert("leaf-02", "api.example.com", org="Acme")
    exact = _rule("CN=api.example.com,O=Acme", "exact")
    wildcard = _rule("CN=*.example.com", "wildcard")
    wildcard_with_org = _rule("CN=*.example.com,O=Acme", "wildcard-org")

    exact_score = rule_score(exact, cert)
    wildcard_score = rule_score(wildcard, cert)
    wildcard_org_score = rule_score(wildcard_with_org, cert)

    assert isinstance(exact_score, int)
    assert exact_score > wildcard_org_score > wildcard_score
    assert pick_rule([wildcard, exact], cert)["account"] == "exact"


def test_03_equal_score_rules_keep_declaration_order():
    cert = _cert("leaf-03", "api.example.com", org="Acme")
    first = _rule("CN=api.example.com,O=Acme", "first")
    second = _rule("CN=api.example.com,O=Acme", "second")

    assert rule_score(first, cert) == rule_score(second, cert)
    assert pick_rule([first, second], cert)["account"] == "first"
    assert pick_rule([second, first], cert)["account"] == "second"


def test_04_normalize_name_canonicalizes_attribute_order():
    canonical = "cn=api.example.com,o=acme,ou=platform"
    assert normalize_name("CN=api.example.com,O=Acme,OU=Platform") == canonical
    assert normalize_name("OU=Platform, O=Acme, CN=api.example.com") == canonical

    cert = _cert("leaf-04", "api.example.com", org="Acme", ou="Platform")
    assert (
        match_rule(
            _rule("O=Acme,OU=Platform,CN=api.example.com"),
            cert,
        )
        is True
    )


def test_05_normalize_name_strips_case_and_whitespace():
    assert normalize_name("  CN =  Alice  , O = Acme ") == "cn=alice,o=acme"
    cert = _cert("leaf-05", " Alice ", org="  Acme  ")
    assert match_rule(_rule("CN=Alice,O=Acme"), cert) is True


def test_06_subject_of_prefers_extension_then_common_name():
    extension_cert = _cert(
        "leaf-06a",
        "api.example.com",
        account="svc-billing",
    )
    fallback_cert = _cert(
        "leaf-06b",
        "fallback.example.net",
        issuer=("CA-B", "Acme"),
        serial="1002",
    )
    blank_cert = _cert("leaf-06c", "x.example.org", account="   ")

    assert subject_of(extension_cert) == "svc-billing"
    assert subject_of(fallback_cert) == "fallback.example.net"
    assert subject_of(blank_cert) == "x.example.org"

    policy = {
        "rules": [
            {"pattern": "CN=*.example.com"},
            {"pattern": "CN=fallback.example.net"},
        ]
    }
    result = map_batch([extension_cert, fallback_cert], policy, NOW)
    assert result["mapped"] == {
        "leaf-06a": "svc-billing",
        "leaf-06b": "fallback.example.net",
    }
    assert result["rejected"] == {}


def test_07_revocation_requires_issuer_and_serial_together():
    cert = _cert(
        "leaf-07",
        "api.example.com",
        issuer=("CA-A", "Acme"),
        serial="1001",
    )
    other_issuer = [
        {
            "issuer": {"CN": "CA-B", "O": "Acme"},
            "serial": "1001",
        }
    ]
    matching = [
        {
            "issuer": {"CN": "CA-A", "O": "Acme"},
            "serial": "1001",
            "revoked_at": "2026-01-01T00:00:00Z",
        }
    ]
    future = [
        {
            "issuer": {"CN": "CA-A", "O": "Acme"},
            "serial": "1001",
            "revoked_at": "2027-01-01T00:00:00Z",
        }
    ]

    assert check_revocation(cert, other_issuer, NOW) is False
    assert check_revocation(cert, matching, NOW) is True
    assert check_revocation(cert, future, NOW) is False


def test_08_same_certificate_cannot_map_to_two_accounts():
    first = _cert(
        "leaf-08a",
        "alice.example.com",
        issuer=("CA-A", "Acme"),
        serial="7001",
    )
    duplicate_identity = _cert(
        "leaf-08b",
        "bob.example.com",
        issuer=("CA-A", "Acme"),
        serial="7001",
    )
    policy = {
        "rules": [
            _rule("CN=alice.example.com,O=Acme", "alice-acct"),
            _rule("CN=bob.example.com,O=Acme", "bob-acct"),
        ]
    }

    result = map_batch([first, duplicate_identity], policy, NOW)
    assert result["mapped"] == {"leaf-08a": "alice-acct"}
    assert result["rejected"] == {"leaf-08b": "duplicate_certificate"}


def test_09_empty_mapping_rule_set_is_rejected():
    cert = _cert("leaf-09", "api.example.com")
    with pytest.raises(ValueError):
        map_batch([cert], {"rules": []}, NOW)


def test_10_batch_must_not_reuse_first_certificate_rule_for_second():
    first = _cert(
        "leaf-10a",
        "api.example.com",
        org="Acme",
    )
    second = _cert(
        "leaf-10b",
        "admin.other.net",
        org="Other",
        issuer=("CA-B", "Other"),
        serial="1002",
    )
    policy = {
        "rules": [
            _rule("CN=api.example.com,O=Acme", "svc-api"),
            _rule("CN=*.other.net,O=Other", "ops"),
        ]
    }

    result = map_batch([first, second], policy, NOW)
    assert result["mapped"] == {
        "leaf-10a": "svc-api",
        "leaf-10b": "ops",
    }
    assert result["rejected"] == {}


def test_11_exact_rule_hit_and_certificate_parse():
    raw = {
        "id": "leaf-11",
        "subject": "CN=api.example.com, O=Acme, OU=Platform",
        "issuer": "CN=Corp Client CA, O=Acme",
        "serial": "1001",
        "extensions": {"clientAccount": "svc-api"},
    }
    parsed = parse_cert(raw)

    assert parsed["id"] == "leaf-11"
    assert parsed["subject"]["cn"] == "api.example.com"
    assert parsed["subject"]["o"] == "acme"
    assert parsed["subject"]["ou"] == "platform"
    assert parsed["issuer"]["cn"] == "corp client ca"
    assert parsed["issuer"]["o"] == "acme"
    assert parsed["serial"] == "1001"
    assert parsed["extensions"]["clientAccount"] == "svc-api"

    exact = _rule("CN=api.example.com,O=Acme", "svc-api")
    broad = _rule("CN=*.example.com", "broad")
    assert match_rule(exact, parsed) is True
    assert pick_rule([broad, exact], parsed)["account"] == "svc-api"


def test_12_wildcard_rule_hits_one_leftmost_label():
    cert = _cert("leaf-12", "api.example.com")
    wildcard = _rule("CN=*.example.com", "single-label")

    assert match_rule(wildcard, cert) is True
    assert match_rule(wildcard, _cert("leaf-12b", "example.com")) is False
    assert pick_rule([wildcard], cert)["account"] == "single-label"


def test_13_more_specific_rule_wins_over_wildcard():
    cert = _cert("leaf-13", "api.example.com", org="Acme")
    broad = _rule("CN=*.example.com", "broad")
    specific = _rule("CN=api.example.com,O=Acme", "specific")

    assert pick_rule([broad, specific], cert)["account"] == "specific"
    assert pick_rule([specific, broad], cert)["account"] == "specific"


def test_14_revoked_certificate_is_rejected_by_batch():
    revoked_cert = _cert(
        "leaf-14-bad",
        "api.example.com",
        issuer=("CA-A", "Acme"),
        serial="1001",
    )
    live_cert = _cert(
        "leaf-14-good",
        "api.example.com",
        issuer=("CA-B", "Acme"),
        serial="1001",
    )
    policy = {
        "rules": [_rule("CN=*.example.com", "svc")],
        "revoked": [
            {
                "issuer": "CN=CA-A,O=Acme",
                "serial": "1001",
                "revoked_at": "2026-01-01T00:00:00Z",
            }
        ],
    }

    result = map_batch([revoked_cert, live_cert], policy, NOW)
    assert result["mapped"] == {"leaf-14-good": "svc"}
    assert result["rejected"] == {"leaf-14-bad": "revoked"}


def test_15_two_batches_match_independent_single_mappings():
    first = _cert("leaf-15a", "api.example.com", org="Acme", serial="1501")
    second = _cert(
        "leaf-15b",
        "jobs.example.org",
        org="Jobs",
        issuer=("CA-B", "Jobs"),
        serial="1502",
    )
    policy = {
        "rules": [
            _rule("CN=api.example.com,O=Acme", "acct-a"),
            _rule("CN=jobs.example.org,O=Jobs", "acct-b"),
        ]
    }

    single_first = map_batch([first], policy, NOW)
    single_second = map_batch([second], policy, NOW)
    batch_ab = map_batch([first, second], policy, NOW)
    batch_ba = map_batch([second, first], policy, NOW)

    assert single_first["mapped"] == {"leaf-15a": "acct-a"}
    assert single_second["mapped"] == {"leaf-15b": "acct-b"}
    assert batch_ab["mapped"] == {
        "leaf-15a": "acct-a",
        "leaf-15b": "acct-b",
    }
    assert batch_ba["mapped"] == {
        "leaf-15b": "acct-b",
        "leaf-15a": "acct-a",
    }
    assert batch_ab["rejected"] == {}
    assert batch_ba["rejected"] == {}