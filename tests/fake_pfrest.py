"""In-memory pfrest v2 server for unit tests, checking request bodies against the published contract.

It mimics what matters for the Salt modules: ids are list positions (they shift on delete), children
are addressed by parent_id, writes create config history revisions, apply calls are recorded, dry_run
validates without writing. It is a test double, not a reimplementation of pfrest.
"""

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CONTRACT = json.loads((Path(__file__).parent.parent / "pfrest" / "contract" / "v2.10.2.json").read_text())
CONTROL = {"apply", "async", "dry_run", "id", "parent_id", "placement"}
QUERY_CONTROL = {"limit", "offset", "sort_by", "sort_order", "sort_flags", "query"}


@dataclass
class Response:
    status_code: int
    payload: dict[str, Any]

    def json(self) -> dict[str, Any]:
        return self.payload


@dataclass
class Collection:
    singular: str
    plural: str | None = None
    parented: bool = False
    singleton: bool = False


@dataclass
class FakePfrest:
    collections: list[Collection]
    data: dict[str, Any] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)
    requests: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    revisions: list[dict[str, Any]] = field(default_factory=lambda: [{"time": 1, "description": "initial"}])

    def __post_init__(self) -> None:
        self._by_path: dict[str, tuple[Collection, bool]] = {}
        for collection in self.collections:
            self._by_path[collection.singular] = (collection, False)
            if collection.plural:
                self._by_path[collection.plural] = (collection, True)
            self.data.setdefault(collection.singular, {} if (collection.parented or collection.singleton) else [])

    # helpers for tests
    # =========================================================================

    def objects(self, singular: str, parent_id: Any = None) -> Any:
        store = self.data[singular]
        return store.setdefault(parent_id, []) if parent_id is not None else store

    def external_write(self, description: str = "webgui") -> None:
        """Simulate a write by someone else (WebGUI, HA sync)."""
        self.revisions.append({"time": self.revisions[-1]["time"] + 1, "description": description})

    # session interface used by PfrestClient
    # =========================================================================

    def request(self, method: str, url: str, params: Any = None, json: Any = None, **kwargs: Any) -> Response:
        path = urlparse(url).path.split("/api/v2/", 1)[1]
        params = dict(params or {})
        body = dict(json or {})
        self.requests.append((method, path, dict(params, **body)))
        if path == "diagnostics/config_history/revisions":
            return self._ok(copy.deepcopy(self.revisions))
        if path.endswith("/apply"):
            if method == "POST":
                self.applied.append(path)
            return self._ok({"applied": True})
        if path not in self._by_path:
            return self._error(404, "ENDPOINT_NOT_FOUND", path)
        collection, plural = self._by_path[path]
        if method == "GET":
            return self._get(collection, plural, params)
        if method == "DELETE":
            return self._delete(collection, params)
        error = self._validate(path, method.lower(), body)
        if error:
            return error
        return self._write(collection, method, body)

    def _ok(self, data: Any) -> Response:
        return Response(200, {"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": data})

    def _error(self, code: int, response_id: str, message: str) -> Response:
        return Response(code, {"code": code, "status": "bad request", "response_id": response_id, "message": message})

    def _validate(self, path: str, method: str, body: dict[str, Any]) -> Response | None:
        spec = CONTRACT["endpoints"].get(path, {}).get(method)
        if spec is None:
            return self._error(405, "METHOD_NOT_ALLOWED", "{0} {1}".format(method, path))
        model = CONTRACT["models"].get(spec.get("model") or "", {})
        for name in body:
            if name in CONTROL:
                continue
            if name not in model:
                return self._error(400, "FIELD_UNKNOWN", name)
            if model[name].get("readOnly"):
                return self._error(400, "FIELD_READ_ONLY", name)
        missing = [name for name in spec.get("required", []) if name not in body]
        if missing:
            return self._error(400, "FIELD_REQUIRED", ",".join(missing))
        return None

    def _listing(self, collection: Collection, parent_id: Any = None) -> list[dict[str, Any]]:
        if collection.parented:
            parents = [parent_id] if parent_id is not None else list(self.data[collection.singular])
            return [
                dict(obj, id=index, parent_id=parent)
                for parent in parents
                for index, obj in enumerate(self.objects(collection.singular, parent))
            ]
        return [dict(obj, id=index) for index, obj in enumerate(self.data[collection.singular])]

    def _get(self, collection: Collection, plural: bool, params: dict[str, Any]) -> Response:
        if collection.singleton:
            return self._ok(copy.deepcopy(self.data[collection.singular]))
        listing = self._listing(collection, params.pop("parent_id", None))
        if plural:
            filters = {k: v for k, v in params.items() if k not in QUERY_CONTROL}
            return self._ok([obj for obj in listing if all(obj.get(k) == v for k, v in filters.items())])
        matches = [obj for obj in listing if obj["id"] == int(params["id"])]
        return self._ok(matches[0]) if matches else self._error(404, "MODEL_OBJECT_NOT_FOUND", str(params))

    def _write(self, collection: Collection, method: str, body: dict[str, Any]) -> Response:
        dry_run = body.pop("dry_run", False)
        for name in ("apply", "async"):
            body.pop(name, None)
        if collection.singleton:
            if not dry_run:
                self.data[collection.singular].update(body)
                self.external_write("api")
            return self._ok(copy.deepcopy(self.data[collection.singular]))
        parent_id = body.pop("parent_id", None)
        store = self.objects(collection.singular, parent_id) if collection.parented else self.data[collection.singular]
        placement = body.pop("placement", None)
        if method == "POST":
            obj = body
            index = len(store) if placement is None else min(int(placement), len(store))
            if not dry_run:
                store.insert(index, obj)
                self.external_write("api")
            return self._ok(dict(obj, id=index))
        index = int(body.pop("id"))
        if index >= len(store):
            return self._error(404, "MODEL_OBJECT_NOT_FOUND", str(index))
        if not dry_run:
            store[index].update(body)
            self.external_write("api")
        return self._ok(dict(store[index], id=index))

    def _delete(self, collection: Collection, params: dict[str, Any]) -> Response:
        parent_id = params.get("parent_id")
        store = self.objects(collection.singular, parent_id) if collection.parented else self.data[collection.singular]
        index = int(params["id"])
        if index >= len(store):
            return self._error(404, "MODEL_OBJECT_NOT_FOUND", str(index))
        obj = store[index]
        if not params.get("dry_run"):
            del store[index]
            self.external_write("api")
        return self._ok(dict(obj, id=index))
