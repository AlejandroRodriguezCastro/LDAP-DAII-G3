from pymongo import MongoClient
from typing import Any
import structlog
from app.config.settings import settings

logger = structlog.get_logger(__name__)

class NonRelationalDBPort:
    def __init__(self, non_relational_db: MongoClient, db_name: str = settings.MONGO_DB_NAME):
        logger.info("Initializing NonRelationalDBPort", db_name=db_name)
        self.client = non_relational_db
        self.db = self.client[db_name]
    
    def delete_many(self, collection_name: str, filter: dict) -> int:
        collection = self.get_collection(collection_name)
        result = collection.delete_many(filter)
        logger.info("Bulk deleted entries", collection_name=collection_name, filter=filter, deleted_count=result.deleted_count)
        return result.deleted_count

    def get_collection(self, collection_name: str):
        logger.info("Getting collection", collection_name=collection_name)
        return self.db[collection_name]

    def insert_entry(self, collection_name: str, data: dict[str, Any]) -> str:
        collection = self.get_collection(collection_name)
        result = collection.insert_one(data)
        logger.info("Inserted entry", collection_name=collection_name, inserted_id=str(result.inserted_id))
        return str(result.inserted_id)

    def find_entry(self, collection_name: str, query: dict[str, Any]) -> Any:
        collection = self.get_collection(collection_name)
        logger.info("Finding entry", collection_name=collection_name, query=query)
        return collection.find_one(query)

    def find_entries(self, collection_name: str, query: dict[str, Any] = None) -> list[dict[str, Any]]:
        collection = self.get_collection(collection_name)
        if query is None:
            query = {}
        logger.info("Finding entries", collection_name=collection_name, query=query)
        return list(collection.find(query))

    def update_entry(self, collection_name: str, query: dict[str, Any], update_data: dict[str, Any]) -> int:
        collection = self.get_collection(collection_name)
        result = collection.update_one(query, {"$set": update_data})
        logger.info("Updated entry", collection_name=collection_name, query=query, update_data=update_data)
        return result.modified_count

    def delete_entry(self, collection_name: str, query: dict[str, Any]) -> int:
        collection = self.get_collection(collection_name)
        result = collection.delete_one(query)
        logger.info("Deleted entry", collection_name=collection_name, query=query)
        return result.deleted_count
    
