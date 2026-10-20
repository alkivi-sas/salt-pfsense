"""EXP-01 (V1) on the fake server: writes keyed by natural key never hit another object.

1000 random operations (create, delete, update) are interleaved with insertions and deletions by a
third party, which shift every position id. After each update the targeted object must carry the new
value and every other object must be unchanged. Run against the test double, not a real pfrest.
"""

import random

import pfrest
from fake_pfrest import Collection, FakePfrest

ITERATIONS = 1000


def test_natural_key_writes_under_shifting_ids() -> None:
    rng = random.Random(20261020)
    server = FakePfrest([Collection("firewall/alias", "firewall/aliases")])
    api = pfrest.PfrestClient(api_key="0" * 64, session=server)
    expected: dict[str, list[str]] = {}
    wrong_writes = 0

    for step in range(ITERATIONS):
        # third party: insert or delete at a random position (WebGUI, other tool)
        store = server.objects("firewall/alias")
        if store and rng.random() < 0.3:
            victim = store.pop(rng.randrange(len(store)))
            expected.pop(victim["name"], None)
        if rng.random() < 0.3:
            name = "EXT_{0}".format(step)
            store.insert(rng.randrange(len(store) + 1), {"name": name, "type": "host", "address": ["192.0.2.1"]})
            expected[name] = ["192.0.2.1"]

        action = rng.choice(["create", "update", "update", "delete"])
        names = sorted(expected)
        if action == "create" or not names:
            name = "SALT_{0}".format(step)
            api.write_checked(
                "POST",
                "firewall/alias",
                "firewall/aliases",
                {"name": name},
                body={"type": "host", "address": ["198.51.100.1"]},
            )
            expected[name] = ["198.51.100.1"]
        elif action == "update":
            name = rng.choice(names)
            value = ["198.51.100.{0}".format(step % 250 + 1)]
            api.write_checked("PATCH", "firewall/alias", "firewall/aliases", {"name": name}, body={"address": value})
            expected[name] = value
        else:
            name = rng.choice(names)
            api.write_checked("DELETE", "firewall/alias", "firewall/aliases", {"name": name})
            expected.pop(name)

        actual = {obj["name"]: obj["address"] for obj in server.objects("firewall/alias")}
        if actual != expected:
            wrong_writes += 1

    assert wrong_writes == 0


def test_cached_ids_do_hit_other_objects() -> None:
    """Counter-example: an id resolved before a third party write targets the wrong object."""
    rng = random.Random(20261020)
    server = FakePfrest([Collection("firewall/alias", "firewall/aliases")])
    api = pfrest.PfrestClient(api_key="0" * 64, session=server)
    for index in range(20):
        api.post("firewall/alias", {"name": "A{0}".format(index), "type": "host", "address": ["192.0.2.1"]})
    wrong_writes = 0
    for step in range(200):
        target = "A{0}".format(rng.randrange(20))
        found = api.find_one("firewall/aliases", allow_missing=True, name=target)
        if found is None:
            continue
        cached_id = found["id"]
        store = server.objects("firewall/alias")
        store.insert(0, store.pop(rng.randrange(len(store))))  # third party reorders
        api.patch("firewall/alias", {"id": cached_id, "descr": "step {0}".format(step)})
        if server.objects("firewall/alias")[cached_id]["name"] != target:
            wrong_writes += 1
    assert wrong_writes > 0
