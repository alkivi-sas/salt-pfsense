"""Normalized diff of two pfSense config.xml files, filtered by a registry of accepted differences.

Usage: python tests/oracle/diff_config.py before.xml after.xml [--registry accepted_diffs.yaml]
Exit code 0 when every difference is accepted, 1 otherwise.
"""

import argparse
import fnmatch
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

# Volatile fields: rewritten on every save or set from the current time
VOLATILE_KEYS = {"revision", "tracker", "created", "updated", "time"}

Diff = tuple[str, Any, Any]


def element_to_data(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        return (element.text or "").strip()
    data: dict[str, Any] = {}
    for child in children:
        value = element_to_data(child)
        if child.tag in data:
            if not isinstance(data[child.tag], list):
                data[child.tag] = [data[child.tag]]
            data[child.tag].append(value)
        else:
            data[child.tag] = value
    return data


def parse_config(path: Path) -> Any:
    return element_to_data(ET.parse(path).getroot())


def normalize(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: normalize(value) for key, value in data.items() if key not in VOLATILE_KEYS}
    if isinstance(data, list):
        return [normalize(item) for item in data]
    return data


def diff(before: Any, after: Any, path: str = "") -> list[Diff]:
    if isinstance(before, dict) and isinstance(after, dict):
        result: list[Diff] = []
        for key in sorted(set(before) | set(after)):
            child = "{0}:{1}".format(path, key) if path else key
            if key not in before:
                result.append((child, None, after[key]))
            elif key not in after:
                result.append((child, before[key], None))
            else:
                result.extend(diff(before[key], after[key], child))
        return result
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        result = []
        for index, (old, new) in enumerate(zip(before, after)):
            result.extend(diff(old, new, "{0}:{1}".format(path, index)))
        return result
    if before != after:
        return [(path, before, after)]
    return []


def load_registry(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.exists():
        return []
    entries = yaml.safe_load(path.read_text()) or []
    for entry in entries:
        if "path" not in entry or "reason" not in entry:
            raise ValueError("registry entry needs path and reason: {0}".format(entry))
    return entries


def unexplained(diffs: list[Diff], registry: list[dict[str, str]]) -> list[Diff]:
    patterns = [entry["path"] for entry in registry]
    return [d for d in diffs if not any(fnmatch.fnmatchcase(d[0], pattern) for pattern in patterns)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--registry", type=Path, default=Path(__file__).with_name("accepted_diffs.yaml"))
    args = parser.parse_args(argv)

    diffs = diff(normalize(parse_config(args.before)), normalize(parse_config(args.after)))
    remaining = unexplained(diffs, load_registry(args.registry))
    for path, old, new in remaining:
        sys.stdout.write("{0}\n  - {1!r}\n  + {2!r}\n".format(path, old, new))
    sys.stdout.write("{0} difference(s), {1} unexplained\n".format(len(diffs), len(remaining)))
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
