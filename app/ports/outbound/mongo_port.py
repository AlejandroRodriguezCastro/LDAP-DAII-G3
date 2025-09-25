from pymongo import MongoClient
from typing import Any

class MongoPort:
    def __init__(self, mongo_client: MongoClient, db_name: str = "ldap-roles", collection_name: str = "roles"):
        self.client = mongo_client
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def insert_role(self, role_data: dict[str, Any]) -> str:
        result = self.collection.insert_one(role_data)
        return str(result.inserted_id)
