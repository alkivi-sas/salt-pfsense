import copy
import importlib.util
import itertools
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest

ROOT = Path(__file__).resolve().parent.parent

# The Salt loader exposes _utils/*.py as top-level modules (`import pfsense`)
sys.path.insert(0, str(ROOT / "_utils"))

_counter = itertools.count()


class FakeFauxapi:
    """In-memory stand-in for pfsense.FauxapiLib: keeps a config dict and records calls."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.calls: list[tuple[str, Any]] = []

    def config_get(self, section: str | None = None) -> Any:
        self.calls.append(("config_get", section))
        data = copy.deepcopy(self.config)
        return data if section is None else data[section]

    def config_set(self, config: dict[str, Any], section: str | None = None) -> dict[str, Any]:
        self.calls.append(("config_set", section))
        if section is None:
            self.config = copy.deepcopy(config)
        else:
            self.config[section] = copy.deepcopy(config)
        return {"message": "ok"}

    def config_patch(self, config: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("config_patch", list(config)))
        _merge(self.config, copy.deepcopy(config))
        return {"message": "ok"}

    def send_event(self, command: str) -> dict[str, Any]:
        self.calls.append(("send_event", command))
        return {"message": "ok"}

    def function_call(self, data: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("function_call", data))
        return {"message": "ok"}


def _merge(target: dict[str, Any], patch: dict[str, Any]) -> None:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = value


Loader = Callable[..., ModuleType]


@pytest.fixture
def load_module() -> Loader:
    """Load a Salt module or state file with the dunders the Salt loader would inject."""

    def _load(relpath: str, **dunders: Any) -> ModuleType:
        path = ROOT / relpath
        name = "salt_pfsense_test_{0}_{1}".format(path.stem, next(_counter))
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        defaults: dict[str, Any] = {
            "__salt__": {},
            "__context__": {},
            "__opts__": {"test": False},
            "__pillar__": {},
            "__grains__": {},
        }
        defaults.update(dunders)
        for key, value in defaults.items():
            setattr(module, key, value)
        return module

    return _load


@pytest.fixture
def fake_fauxapi() -> Callable[[dict[str, Any]], FakeFauxapi]:
    return FakeFauxapi
