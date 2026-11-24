"""客户端证书到账号映射的唯一实现文件。

这里恰好保留八个公开桩；每个桩在初始状态下都必须抛出 NotImplementedError。
修复时只填充这八个桩，不新增公开入口，也不要把实现放到其他模块。
"""

from __future__ import annotations

from datetime import datetime
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


def parse_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """解析主体、签发者、扩展项和序列号，返回规范化证书。"""
    raise NotImplementedError("parse_cert")


def normalize_name(name: str) -> str:
    """规范化名称的大小写、空白和属性顺序。"""
    raise NotImplementedError("normalize_name")


def rule_score(rule: dict[str, Any], cert: dict[str, Any]) -> int:
    """计算规则具体度评分，精确匹配高于通配且属性越多分越高。"""
    raise NotImplementedError("rule_score")


def match_rule(rule: dict[str, Any], cert: dict[str, Any]) -> bool:
    """判断规则是否匹配，通配只能位于最左标签且不跨点。"""
    raise NotImplementedError("match_rule")


def pick_rule(
    rules: list[dict[str, Any]], cert: dict[str, Any]
) -> dict[str, Any]:
    """选最高分规则，同分时按声明顺序取第一条。"""
    raise NotImplementedError("pick_rule")


def subject_of(cert: dict[str, Any]) -> str:
    """返回映射账号名，扩展项优先，缺失时回退到通用名。"""
    raise NotImplementedError("subject_of")


def check_revocation(
    cert: dict[str, Any], revoked: list[dict[str, Any]], now: datetime
) -> bool:
    """检查证书是否已撤销，序列号与签发者必须共同匹配。"""
    raise NotImplementedError("check_revocation")


def map_batch(
    certs: list[dict[str, Any]], policy: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """批量映射证书，每张证书独立处理并保证身份唯一。"""
    raise NotImplementedError("map_batch")