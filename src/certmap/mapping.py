"""客户端证书到账号映射的唯一实现文件。

这里恰好保留八个公开桩；每个桩在初始状态下都必须抛出 NotImplementedError。
修复时只填充这八个桩，不新增公开入口，也不要把实现放到其他模块。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

__all__ = [
    "parse_cert",
    "normalize_name",
    "rule_score",
    "match_rule",
    "pick_rule",
    "subject_of",
    "check_revocation",
    "map_batch",
]


def _clean(value: Any) -> str:
    """去掉首尾空白并把内部连续空白折叠成一个空格，最后转小写。"""
    return " ".join(str(value).split()).lower()


def _split_dn(dn: str) -> list[tuple[str, str]]:
    """把逗号分隔的 DN 拆成 (小写属性名, 规范化属性值) 列表。"""
    pairs: list[tuple[str, str]] = []
    for chunk in dn.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        key = _clean(key)
        if not key:
            continue
        pairs.append((key, _clean(value)))
    return pairs


def _name_parts(name: Any) -> list[tuple[str, str]]:
    """把 dict 或 DN 字符串统一成属性对列表。"""
    if isinstance(name, dict):
        return [(_clean(key), _clean(value)) for key, value in name.items()]
    if isinstance(name, str):
        return _split_dn(name)
    return []


def _canonical_name(name: Any) -> str:
    """把 dict 或 DN 字符串规范化成排序后的 key=value 串。"""
    pairs = sorted(_name_parts(name), key=lambda pair: pair[0])
    return ",".join(f"{key}={value}" for key, value in pairs)


def _matches_value(key: str, pattern_value: str, subject_value: str) -> bool:
    """按标签比较单个属性值，通配符只允许独占最左标签且只匹配一个标签。"""
    if "*" not in pattern_value:
        return pattern_value == subject_value

    # 通配符只允许出现在 CN，其他属性出现通配一律视为非法。
    if key != "cn":
        return False

    pattern_labels = pattern_value.split(".")
    # 通配符必须恰好一个、独占最左标签，且其余标签不得含通配。
    if pattern_labels[0] != "*":
        return False
    if any("*" in label for label in pattern_labels[1:]):
        return False

    subject_labels = subject_value.split(".")
    if len(subject_labels) != len(pattern_labels):
        return False
    if not subject_labels[0]:
        return False
    return subject_labels[1:] == pattern_labels[1:]


def _matches_rule_parts(
    rule_parts: list[tuple[str, str]], subject: dict[str, str]
) -> bool:
    if not rule_parts:
        return False
    for key, value in rule_parts:
        if key not in subject:
            return False
        if not _matches_value(key, value, subject[key]):
            return False
    return True


def _parse_time(value: Any) -> datetime | None:
    """解析 ISO 时间，支持 Z 后缀，统一成带时区的 datetime。"""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """解析主体、签发者、扩展项和序列号，返回规范化证书。"""
    subject = {key: value for key, value in _name_parts(cert.get("subject"))}
    issuer = {key: value for key, value in _name_parts(cert.get("issuer"))}
    serial = str(cert.get("serial", "")).strip()
    extensions = cert.get("extensions") or {}
    return {
        "id": cert.get("id"),
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "extensions": dict(extensions),
    }


def normalize_name(name: str) -> str:
    """规范化名称的大小写、空白和属性顺序。"""
    return _canonical_name(name)


def rule_score(rule: dict[str, Any], cert: dict[str, Any]) -> int:
    """计算规则具体度评分，精确匹配高于通配且属性越多分越高。"""
    pattern = rule.get("pattern")
    if not isinstance(pattern, str):
        return 0
    rule_parts = _split_dn(pattern)
    subject = parse_cert(cert)["subject"]
    if not _matches_rule_parts(rule_parts, subject):
        return 0

    hits = len(rule_parts)
    if any("*" in value for _, value in rule_parts):
        # 含通配的规则只按命中属性数评分，始终低于精确规则。
        return 10 * hits
    return 1000 + 10 * hits


def match_rule(rule: dict[str, Any], cert: dict[str, Any]) -> bool:
    """判断规则是否匹配，通配只能位于最左标签且不跨点。"""
    pattern = rule.get("pattern")
    if not isinstance(pattern, str):
        return False
    rule_parts = _split_dn(pattern)
    subject = parse_cert(cert)["subject"]
    return _matches_rule_parts(rule_parts, subject)


def pick_rule(
    rules: list[dict[str, Any]], cert: dict[str, Any]
) -> dict[str, Any]:
    """选最高分规则，同分时按声明顺序取第一条。"""
    best: dict[str, Any] = {}
    best_score = 0
    for rule in rules:
        score = rule_score(rule, cert)
        # 严格大于才替换，因此同分保留最先声明的那条。
        if score > best_score:
            best_score = score
            best = rule
    return best


def subject_of(cert: dict[str, Any]) -> str:
    """返回映射账号名，扩展项优先，缺失时回退到通用名。"""
    parsed = parse_cert(cert)
    extensions = parsed["extensions"]
    account = extensions.get("clientAccount")
    if isinstance(account, str):
        account = account.strip()
        if account:
            return account
    return parsed["subject"].get("cn", "")


def check_revocation(
    cert: dict[str, Any], revoked: list[dict[str, Any]], now: datetime
) -> bool:
    """检查证书是否已撤销，序列号与签发者必须共同匹配。"""
    parsed = parse_cert(cert)
    cert_issuer = _canonical_name(parsed["issuer"])
    cert_serial = parsed["serial"]
    current = _parse_time(now)

    for entry in revoked:
        entry_issuer = _canonical_name(entry.get("issuer"))
        entry_serial = str(entry.get("serial", "")).strip()
        # 签发者与序列号必须同时匹配，避免跨签发者误判。
        if entry_issuer != cert_issuer or entry_serial != cert_serial:
            continue

        revoked_at = entry.get("revoked_at")
        if revoked_at is None or revoked_at == "":
            return True
        effective_at = _parse_time(revoked_at)
        if effective_at is not None and current is not None and effective_at <= current:
            return True

    return False


def map_batch(
    certs: list[dict[str, Any]], policy: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """批量映射证书，每张证书独立处理并保证身份唯一。"""
    rules = policy.get("rules") if isinstance(policy, dict) else None
    if not isinstance(rules, list) or not rules:
        raise ValueError("policy rules must be a non-empty list")

    revoked = policy.get("revoked") or []
    mapped: dict[str, Any] = {}
    rejected: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()

    for raw_cert in certs:
        cert = parse_cert(raw_cert)
        cert_id = cert["id"]
        identity = (_canonical_name(cert["issuer"]), cert["serial"])

        # 同一证书身份只允许在批次中首次出现时被处理。
        if identity in seen:
            rejected[cert_id] = "duplicate_certificate"
            continue
        seen.add(identity)

        if check_revocation(cert, revoked, now):
            rejected[cert_id] = "revoked"
            continue

        # 每张证书都重新计算规则与账号，绝不沿用上一张证书的状态。
        rule = pick_rule(rules, cert)
        if not rule:
            rejected[cert_id] = "no_rule"
            continue

        account = rule.get("account")
        if isinstance(account, str) and account.strip():
            mapped[cert_id] = account.strip()
        else:
            mapped[cert_id] = subject_of(cert)

    return {"mapped": mapped, "rejected": rejected}
