from typing import Any

from conftest import Loader


class Rule:
    def to_dict(self) -> dict[str, str]:
        return {"descr": "old rule", "interface": "lan"}


def test_absent_removes_existing_rule(load_module: Loader) -> None:
    removed: list[Any] = []

    def rm_rule(*args: Any) -> bool:
        removed.append(args)
        return True

    salt = {"pfsense_filter_rule.get_rule": lambda *args: Rule(), "pfsense_filter_rule.rm_rule": rm_rule}
    state = load_module("_states/pfsense_filter_rule.py", __salt__=salt)
    ret = state.absent("old rule", interface="lan")
    assert removed == [("old rule", "lan", None)]
    assert ret["changes"] == {"descr": "old rule", "interface": "lan"}
    assert ret["result"] is True
