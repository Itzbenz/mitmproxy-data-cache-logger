import datetime
import hashlib
import mimetypes
import os

import magic
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi


def generate_index_data(binary: bytes) -> dict:
    index_data = {
        "key": hash_data(binary),
        "updated_at": datetime.datetime.now().isoformat(),
        "data": binary,
        "data_size": len(binary),
    }
    if len(binary) > 0:
        index_data["mime"] = magic.from_buffer(binary, mime=True).strip()
        index_data["extension"] = mimetypes.guess_extension(index_data["mime"].strip(), strict=False)
    return index_data


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
        compressor = os.getenv("MONGO_COMPRESSOR") or "zstd"
        self.client: AsyncIOMotorClient = AsyncIOMotorClient(mongo_url, server_api=ServerApi("1"), compressors=compressor, zlibCompressionLevel=9)
        self.db = self.client[os.getenv("MONGO_DB_NAME") or "mitmproxy"]
        self.metadata_collection = self.db["metadata"]
        self.data_collection = self.db["data"]
        self.metadata_collection.create_index("key", unique=True)
        self.data_collection.create_index("key", unique=True)

    async def set(self, binary: bytes, index_data=None) -> str:
        if index_data is None:
            index_data = {}
        index_data.update(generate_index_data(binary))
        hashed = index_data["key"]
        # update or create
        await self.data_collection.update_one({"key": hashed}, {"$set": index_data}, upsert=True)
        return hashed

    async def get(self, key: str) -> tuple[bytes, dict | None] | None:
        raw_data = await self.data_collection.find_one({"key": key})
        if raw_data is None:
            return None
        data = raw_data["data"]
        if data is None:
            return None

        await self.data_collection.update_one({"key": key}, {"$set": {
            'last_accessed': datetime.datetime.now().isoformat(),
            'hits': raw_data.get('hits', 0) + 1
        }})
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
        await self.metadata_collection.update_one({"key": key}, {"$set": metadata}, upsert=True)


import json


class FileCacheProvider(AbstractCacheProvider):
    def __init__(self):
        super().__init__()
        self.cache_dir = os.getenv("CACHE_DIR") or "./cache"
        os.makedirs(self.cache_dir, exist_ok=True)

    async def set(self, binary: bytes, index_data=None) -> str:
        # index_data is ignored
        index = generate_index_data(binary)
        hashed = index["key"]
        extension = index.get("extension", "")
        with open(os.path.join(self.cache_dir, hashed + extension), "wb") as f:
            f.write(binary)
            return hashed

    async def get(self, key: str) -> tuple[bytes, dict | None] | None:
        with open(os.path.join(self.cache_dir, key), "rb") as f:
            data = f.read()
            return data, None

    async def get_metadata(self, key: str) -> dict | None:
        with open(os.path.join(self.cache_dir, key), "rb") as f:
            raw_data = json.loads(f.read())
            return raw_data

    async def set_metadata(self, key: str, metadata: dict):
        # set or update
        with open(os.path.join(self.cache_dir, key), "wb") as f:
            f.write(json.dumps(metadata).encode())
