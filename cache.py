import datetime
import hashlib
import os


from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi

def hash_data(binary: bytes) -> str:
    return hashlib.sha256(binary).hexdigest()


class AbstractCacheProvider:
    """
    metadata and data is separated to optimize for storage
    there may be multiple metadata entries for one data entry
    """

    def __init__(self):
        pass

    """
    Add cache to the database, return hashed key
    index_data is for database query optimization, it is not used in the actual cache
    """

    async def set(self, binary: bytes, index_data: dict = None) -> str:
        pass

    """
    Get cache from the database, return bytes and additional data or None
    """

    async def get(self, key: str) -> tuple[bytes, dict | None] | None:
        pass

    async def set_metadata(self, key: str, metadata: dict):
        pass

    async def get_metadata(self, key: str) -> dict | None:
        pass


class MongoCacheProvider(AbstractCacheProvider):
    def __init__(self):
        super().__init__()
        mongo_url = os.getenv("MONGO_URL") or "mongodb://localhost:27017"
        self.client: AsyncIOMotorClient = AsyncIOMotorClient(mongo_url, server_api=ServerApi("1"))
        self.db = self.client[os.getenv("MONGO_DB_NAME") or "mitmproxy"]
        self.metadata_collection = self.db["metadata"]
        self.data_collection = self.db["data"]
        self.metadata_collection.create_index("key", unique=True)
        self.data_collection.create_index("key", unique=True)

    async def set(self, binary: bytes, index_data=None) -> str:
        if index_data is None:
            index_data = {}
        hashed = hash_data(binary)

        index_data["key"] = hashed
        index_data["created_at"] = datetime.datetime.now().isoformat()
        index_data["data"] = binary
        index_data["data_size"] = len(binary)
        # add or update
        if await self.data_collection.count_documents({"key": hashed}) > 0:
            await self.data_collection.update_one({"key": hashed}, {"$set": index_data})
        else:
            await self.data_collection.insert_one(index_data)
        return hashed

    async def get(self, key: str) -> tuple[bytes, dict | None] | None:
        raw_data = await self.data_collection.find_one({"key": key})
        if raw_data is None:
            return None
        data = raw_data["data"]
        if data is None:
            return None
        index_data = raw_data.copy()
        index_data.pop("_id")
        index_data.pop("data")
        index_data.pop("key")
        return data, raw_data

    async def get_metadata(self, key: str) -> dict | None:
        metadata = await self.metadata_collection.find_one({"key": key})
        if metadata is None:
            return None
        return metadata

    async def set_metadata(self, key: str, metadata: dict):
        # set or update

        if await self.metadata_collection.count_documents({"key": key}) > 0:
            await self.metadata_collection.update_one({"key": key}, {"$set": metadata})
        else:
            metadata["key"] = key
            await self.metadata_collection.insert_one(metadata)
