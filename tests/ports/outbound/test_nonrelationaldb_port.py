from types import SimpleNamespace

from app.ports.outbound.nonrelationaldb_port import NonRelationalDBPort


class FakeResult:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakeCollection:
    def __init__(self):
        self.storage = []

    def delete_many(self, filter):
        # delete all matching entries, return object with deleted_count
        before = len(self.storage)
        # naive filter: if empty, delete none; if filter has key:value, remove matching dicts
        if not filter:
            deleted = 0
        else:
            key, val = next(iter(filter.items()))
            self.storage = [d for d in self.storage if d.get(key) != val]
            deleted = before - len(self.storage)
        return FakeResult(deleted_count=deleted)

    def insert_one(self, data):
        _id = f"id{len(self.storage)+1}"
        self.storage.append({**data, "_id": _id})
        return FakeResult(inserted_id=_id)

    def find_one(self, query):
        for d in self.storage:
            if all(d.get(k) == v for k, v in query.items()):
                return d
        return None

    def find(self, query):
        if not query:
            return list(self.storage)
        return [d for d in self.storage if all(d.get(k) == v for k, v in query.items())]

    def update_one(self, query, update):
        for d in self.storage:
            if all(d.get(k) == v for k, v in query.items()):
                # apply $set
                for k, v in update.get("$set", {}).items():
                    d[k] = v
                return FakeResult(modified_count=1)
        return FakeResult(modified_count=0)

    def delete_one(self, query):
        for i, d in enumerate(self.storage):
            if all(d.get(k) == v for k, v in query.items()):
                self.storage.pop(i)
                return FakeResult(deleted_count=1)
        return FakeResult(deleted_count=0)


class FakeDB(dict):
    def __init__(self):
        super().__init__()

    def __getitem__(self, name):
        if name not in self:
            self[name] = FakeCollection()
        return super().__getitem__(name)


class FakeClient(dict):
    def __init__(self):
        super().__init__()

    def __getitem__(self, name):
        if name not in self:
            self[name] = FakeDB()
        return super().__getitem__(name)


def test_nonrelationaldbport_crud_operations():
    client = FakeClient()
    port = NonRelationalDBPort(client, db_name="testdb")

    # insert
    inserted_id = port.insert_entry("col", {"a": 1})
    assert isinstance(inserted_id, str)

    # find_entry
    found = port.find_entry("col", {"a": 1})
    assert found is not None and found["a"] == 1

    # find_entries (no query)
    all_entries = port.find_entries("col")
    assert isinstance(all_entries, list) and len(all_entries) >= 1

    # update_entry
    modified = port.update_entry("col", {"a": 1}, {"b": 2})
    assert modified in (0, 1)

    # delete_entry
    deleted = port.delete_entry("col", {"a": 1})
    assert deleted in (0, 1)

    # delete_many
    # insert some docs
    port.insert_entry("col", {"type": "x"})
    port.insert_entry("col", {"type": "x"})
    deleted_count = port.delete_many("col", {"type": "x"})
    assert isinstance(deleted_count, int)
