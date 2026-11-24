双向认证接进来之后，映射规则先命中通配就停下，结果所有客户端都被映射成了同一个账号：修复客户端证书到账号映射的十个缺陷，它们依次是规则匹配用后缀比较且通配跨点命中；规则评分不区分精确与通配且先命中先返回；同分规则按最后声明取导致结果与声明顺序相反；名称规范化不做属性顺序归一使等价主体被判不同；名称规范化只转小写不去空白使带空格主体匹配失败；主体取值只看通用名而忽略扩展项；撤销检查只比对序列号造成跨签发者误判；映射不检查唯一性使同一证书可映射到多个账号；策略校验缺失允许空映射规则集合；批量映射复用规则集使第二张证书沿用第一张证书的规则。certmap/mapping.py 是核心，tests/test_mapping.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态必须恰好是 15 failed，15 个失败必须全部由 NotImplementedError 触发，不能出现收集错误、导入错误或断言失败。修复完成后应为 15 passed。测试不联网，不读取仓库外文件。

## 字段表

| 字段 | 值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 仓库约束

tests/test_mapping.py 是验收测试，不可修改，不可增加 skip、xfail、夹具，也不可替换或弱化断言。实现只写在 src/certmap/mapping.py，该文件恰好保留 8 个公开桩，每个桩在初始状态下抛出 NotImplementedError；修复时只填充这 8 个桩，不增删公开函数，不把实现散落到其他模块。src/certmap/__init__.py 只再导出这 8 个函数。不要引入第三方包，不要联网，不要执行 git init。

## 布局说明

```text
sec-client-cert-map/
  README.md
  pyproject.toml
  src/
    certmap/
      __init__.py
      mapping.py
  tests/
    test_mapping.py
```

pyproject.toml 通过 `[tool.pytest.ini_options]` 的 `pythonpath = ["src"]` 把 src 布局加入导入路径，因此无需安装包即可在仓库根目录运行测试。tests/test_mapping.py 恰好包含 15 个测试。

## 数据模型

测试中的证书是普通 dict：

```python
cert = {
    "id": "leaf-01",
    "subject": {"CN": "api.example.com", "O": "Acme", "OU": "Platform"},
    "issuer": {"CN": "CA-A", "O": "Acme"},
    "serial": "1001",
    "extensions": {"clientAccount": "svc-api"},
}
```

parse_cert 接受同样形状的 dict，也接受 subject 与 issuer 为 DN 字符串的形式：

```python
raw = {
    "id": "leaf-11",
    "subject": "CN=api.example.com, O=Acme, OU=Platform",
    "issuer": "CN=CA-A, O=Acme",
    "serial": "1001",
    "extensions": {"clientAccount": "svc-api"},
}
```

返回值的键至少包含 id、subject、issuer、serial、extensions。subject 与 issuer 转成小写属性名的 dict，属性值做大小写与空白规范化；extensions 原样保留；serial 转为去掉首尾空白的字符串；缺失的 extensions 按空 dict 处理。DN 只使用逗号分隔的 key=value，不支持转义逗号。

## 名称与规则

normalize_name 处理逗号分隔的 DN：属性名和属性值转小写，去掉等号两侧及逗号两侧空白，把值中的连续空白折叠成一个空格，再按属性名排序，输出逗号分隔且无空格的 key=value 串。例如 CN=Alice,O=Acme 与 o=acme, cn=alice 归一化后相同。

规则形如：

```python
{"pattern": "CN=*.example.com,O=Acme", "account": "svc-edge"}
```

pattern 是 DN 字符串，按属性逐项匹配，主体可以带有规则未列出的属性，但规则列出的属性必须全部存在并相等。通配符只允许出现在 CN，且必须独占最左侧标签；它恰好匹配一个标签，不能跨点，也不能用后缀或子串比较。CN=api.*.example.com 一类的通配位置非法，直接视为不匹配。account 可省略；省略时由 subject_of 从证书推导账号。

rule_score 不匹配时返回 0。匹配时，精确规则返回 1000 加 10 乘以命中属性数，含通配的规则返回 10 乘以命中属性数。因此同类规则属性越多分越高，且精确规则始终高于通配规则。pick_rule 取最高分；同分时取声明顺序中的第一条；没有匹配时返回空 dict。

subject_of 优先读取 extensions 的 clientAccount，去掉首尾空白后非空则返回；否则回退到 subject 的 CN。扩展项为空串或纯空白时也必须回退。

## 撤销与批量结果

check_revocation 的 revoked 是列表，每项形如：

```python
{"issuer": "CN=CA-A,O=Acme", "serial": "1001", "revoked_at": "2026-01-01T00:00:00Z"}
```

issuer 可以是 DN 字符串或 dict。只有规范化后的签发者与序列号同时相等才算命中；revoked_at 省略表示立即生效，存在时只有不晚于 now 才生效。命中且生效返回 True，否则返回 False。

map_batch 校验 policy 的 rules 必须是非空列表，否则抛出 ValueError。成功返回两个 dict：

```python
{
    "mapped": {"leaf-01": "svc-api"},
    "rejected": {"leaf-02": "revoked"},
}
```

每张证书按输入顺序独立处理。证书身份由规范化签发者与序列号共同确定；同一身份在批次中第一次出现时正常处理，后续同身份条目一律进入 rejected，原因码为 duplicate_certificate，不得覆盖或追加账号。已撤销证书进入 rejected，原因码为 revoked；没有命中规则进入 rejected，原因码为 no_rule。规则存在 account 时用它作为映射账号，否则用 subject_of 推导。批量处理不得把上一张证书的匹配规则、分数或账号状态复用到下一张证书。