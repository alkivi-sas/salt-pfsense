from pathlib import Path

import diff_config as oracle

BEFORE = """<?xml version="1.0"?>
<pfsense>
  <revision><time>1</time></revision>
  <aliases>
    <alias><name>ADMIN</name><address>10.0.0.1</address></alias>
  </aliases>
  <filter>
    <rule><descr>a</descr><tracker>100</tracker><log></log></rule>
    <rule><descr>b</descr><tracker>101</tracker></rule>
  </filter>
</pfsense>
"""

AFTER = """<?xml version="1.0"?>
<pfsense>
  <revision><time>2</time></revision>
  <aliases>
    <alias><name>ADMIN</name><address>10.0.0.2</address></alias>
  </aliases>
  <filter>
    <rule><descr>a</descr><tracker>200</tracker><log></log></rule>
    <rule><descr>b</descr><tracker>201</tracker><created><time>5</time></created></rule>
  </filter>
</pfsense>
"""


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def test_parse_repeated_elements_become_list(tmp_path: Path) -> None:
    data = oracle.parse_config(_write(tmp_path, "a.xml", BEFORE))
    assert [rule["descr"] for rule in data["filter"]["rule"]] == ["a", "b"]
    assert data["filter"]["rule"][0]["log"] == ""


def test_volatile_keys_are_ignored(tmp_path: Path) -> None:
    before = oracle.normalize(oracle.parse_config(_write(tmp_path, "a.xml", BEFORE)))
    after = oracle.normalize(oracle.parse_config(_write(tmp_path, "b.xml", AFTER)))
    assert oracle.diff(before, after) == [("aliases:alias:address", "10.0.0.1", "10.0.0.2")]


def test_list_order_matters() -> None:
    before = {"filter": {"rule": [{"descr": "a"}, {"descr": "b"}]}}
    after = {"filter": {"rule": [{"descr": "b"}, {"descr": "a"}]}}
    assert [d[0] for d in oracle.diff(before, after)] == ["filter:rule:0:descr", "filter:rule:1:descr"]


def test_missing_and_added_keys() -> None:
    assert oracle.diff({"a": "1"}, {"b": "2"}) == [("a", "1", None), ("b", None, "2")]


def test_registry_filters_by_glob(tmp_path: Path) -> None:
    registry = _write(tmp_path, "reg.yaml", "- path: 'aliases:alias:*'\n  reason: test\n")
    diffs = [("aliases:alias:address", "x", "y"), ("filter:rule:0:descr", "a", "b")]
    assert oracle.unexplained(diffs, oracle.load_registry(registry)) == [("filter:rule:0:descr", "a", "b")]


def test_main_exit_code(tmp_path: Path) -> None:
    before = _write(tmp_path, "a.xml", BEFORE)
    after = _write(tmp_path, "b.xml", AFTER)
    empty = _write(tmp_path, "empty.yaml", "[]\n")
    accept = _write(tmp_path, "accept.yaml", "- path: 'aliases:*'\n  reason: test\n")
    assert oracle.main([str(before), str(after), "--registry", str(empty)]) == 1
    assert oracle.main([str(before), str(after), "--registry", str(accept)]) == 0
