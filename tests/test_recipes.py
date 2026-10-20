"""Offline checks of the deployment recipes (docs/recipes) and their example files (examples/).

Without a lab the recipes are not applied (T6.5); this checks their structure, that every file they
cite exists, that every example SLS renders and that every state or module function it calls exists.
"""

import re
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RECIPES = sorted((ROOT / "docs" / "recipes").glob("[0-9]*.md"))
EXAMPLES = sorted((ROOT / "examples" / "salt").rglob("*.sls"))
SECTIONS = [
    "## 1. Objectif",
    "## 2. Prérequis",
    "## 3. Pillar",
    "## 4. SLS",
    "## 5. Commande",
    "## 6. Sortie attendue en test=True",
    "## 7. Vérification",
    "## 8. Retour arrière",
    "## 9. Pièges connus",
]


def test_recipes_exist() -> None:
    assert len(RECIPES) >= 30


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda p: p.name)
def test_recipe_structure(recipe: Path) -> None:
    text = recipe.read_text()
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == SECTIONS, recipe.name
    assert text.startswith("# "), recipe.name
    for cited in re.findall(r"`((?:examples|docs|tests|helpers|_modules|_states|_utils)/[^`*<>]+?)`", text):
        assert (ROOT / cited).exists(), "{0} cites missing {1}".format(recipe.name, cited)


def _render(path: Path) -> dict[str, Any]:
    salt = {"pillar.get": lambda key, default=None: default}
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
    # An SLS may render nothing when its guard is false (e.g. fauxapi_absent.sls)
    data = yaml.safe_load(environment.from_string(path.read_text()).render(salt=salt, pillar={}, grains={})) or {}
    assert isinstance(data, dict), path
    return data


def _defines(kind: str, module: str, function: str) -> bool:
    source = ROOT / kind / "{0}.py".format(module)
    return source.exists() and re.search(r"^def {0}\(".format(function), source.read_text(), re.M) is not None


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: str(p.relative_to(ROOT / "examples")))
def test_example_sls(example: Path) -> None:
    for state_id, declaration in _render(example).items():
        assert isinstance(declaration, dict), state_id
        for key, args in declaration.items():
            module, _, function = key.partition(".")
            if key == "module.run":
                for call in args:
                    for target in call:
                        mod, _, fun = target.partition(".")
                        assert _defines("_modules", mod, fun), "{0}: {1}".format(example.name, target)
            elif module.startswith("pfsense_"):
                assert _defines("_states", module, function), "{0}: {1}".format(example.name, key)


def test_example_pillar_is_yaml() -> None:
    data = yaml.safe_load((ROOT / "examples" / "pillar" / "pfsense.sls").read_text())
    assert set(data["pfsense"]) >= {"api_backend", "restapi", "pfrest", "pki", "dhcp_kea"}


@pytest.mark.parametrize(
    "overrides, states",
    [({}, {"fauxapi-package", "/etc/fauxapi"}), ({"pfsense_alias": "fauxapi"}, set())],
)
def test_fauxapi_removal_guard(overrides: dict[str, str], states: set[str]) -> None:
    pillar = {"pfsense:api_backend": "pfrest", "pfsense:api_backend_overrides": overrides}
    salt = {"pillar.get": lambda key, default=None: pillar.get(key, default)}
    template = (ROOT / "examples" / "salt" / "fauxapi_absent.sls").read_text()
    data = yaml.safe_load(jinja2.Environment().from_string(template).render(salt=salt)) or {}
    assert set(data) == states
