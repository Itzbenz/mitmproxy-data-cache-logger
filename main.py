import datetime
import gzip
import random
import time
import traceback
from typing import Dict

from mitmproxy import http

import cache


def guess_magic_bytes(magic_bytes):
    file_ext = ""
    if magic_bytes.startswith(b"\xff\xd8"):
        file_ext = ".jpg"
    elif magic_bytes.startswith(b"\x89\x50\x4e\x47"):
        file_ext = ".png"
    elif magic_bytes.startswith(b"\x47\x49\x46"):
        file_ext = ".gif"
    elif magic_bytes.startswith(b"\x52\x49\x46\x46"):
        file_ext = ".webp"
    elif magic_bytes.startswith(b"\x46\x4c\x56"):
        file_ext = ".flv"
    elif magic_bytes.startswith(b"\x25\x50\x44\x46"):
        file_ext = ".pdf"
    elif magic_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        file_ext = ".webm"
    elif magic_bytes.startswith(b"\x66\x74\x79\x70"):
        file_ext = ".mp4"
    elif magic_bytes.startswith(b"\x4f\x67\x67\x53"):
        file_ext = ".ogg"
    elif magic_bytes.startswith(b"\xff\xfb"):
        file_ext = ".mp3"
    elif magic_bytes.startswith(b"\x4d\x5a"):
        file_ext = ".mid"
    elif magic_bytes.startswith(b"\x50\x4b"):
        file_ext = ".zip"
    elif magic_bytes.startswith(b"\x1f\x8b"):
        file_ext = ".gz"
    elif magic_bytes.startswith(b"\x42\x5a"):
        file_ext = ".bz2"
    elif magic_bytes.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
        file_ext = ".7z"
    else:
        file_ext = ".bin"
    return file_ext


# noinspection PyMethodMayBeStatic
class CacheManager:
    def __init__(self, that_cache_provider: cache.AbstractCacheProvider):
        self.cache_provider = that_cache_provider

    # doesn't adhere to cache control only care about the content
    def should_save_data(self, flow: http.HTTPFlow, data: bytes):
        content_type = flow.response.headers.get("Content-Type", "")
        cache_control = flow.response.headers.get("Cache-Control", "")
        magic_bytes = data[:4]
        file_ext = guess_magic_bytes(magic_bytes)
        reason = ""

        if content_type.startswith("image"):
            reason = reason + f"Is {content_type} "
        if file_ext != ".bin":
            reason = reason + f"File extension {file_ext}"
        reason = reason.strip()
        return "" != reason, reason

    # adhere to cache control
    def should_cache(self, flow: http.HTTPFlow, data: bytes):
        should, reason = self.should_save_data(flow, data)
        reason = reason + " "
        cache_control = flow.response.headers.get("Cache-Control", "")
        content_type = flow.response.headers.get("Content-Type", "")
        should_cache_by_header = True
        if cache_control.startswith("no-cache"):
            should_cache_by_header = False
        if cache_control.startswith("private"):
            should_cache_by_header = False
        if cache_control.startswith("no-store"):
            should_cache_by_header = False
        if cache_control.startswith("max-age=0"):
            should_cache_by_header = False
        if cache_control == "":
            should_cache_by_header = False

        # if content type is image or file_ext isn't bin then save file
        if should_cache_by_header:
            reason = reason + f"Cache Control {cache_control} "
        # trim
        reason = reason.strip()
        should = "" != reason
        if should:
            print(f"Caching {flow.request.pretty_url} because {reason}")
        else:
            print(f"Potential caching {flow.request.method} {flow.request.pretty_url} {content_type} {cache_control}")
        return should, reason

    def guess_type(self, flow: http.HTTPFlow | None, data: bytes) -> str:
        magic_bytes = data[:4]
        file_ext = guess_magic_bytes(magic_bytes)
        if flow is not None and file_ext == ".bin":
            content_type = flow.response.headers.get("Content-Type", "")
            file_ext = content_type.split("/")[-1]
            # have plus ?
            if "+" in file_ext:
                file_ext = file_ext.split("+")[-1]
            if file_ext == "":
                file_ext = "bin"

            file_ext = "." + file_ext
        return file_ext[1:]

    def generate_metadata(self, flow: http.HTTPFlow, data: bytes | None) -> Dict:
        return {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "headers": flow.request.headers,
            "extension": self.guess_type(flow, data),
            "response": {
                "http_version": flow.response.http_version,
                "headers": flow.response.headers,
                "status_code": flow.response.status_code,
            }
        }

    async def generate_or_pull_metadata(self, flow: http.HTTPFlow, data: bytes | None) -> Dict:
        metadata = await self.cache_provider.get_metadata(flow.request.pretty_url)
        if metadata is None:
            metadata = self.generate_metadata(flow, data)
        return metadata

    async def save_metadata(self, metadata: Dict):
        key = metadata["url"]
        if key is None or key == "": raise Exception("Key is None")
        await self.cache_provider.set_metadata(key, metadata)

    async def add_to_cache(self, flow: http.HTTPFlow):
        if flow.response is None: return
        data = flow.response.content
        if data is None:
            print(f"Data is None {flow.request.pretty_url}")
            return
        # check if compression is enabled
        print(f"length {len(data)}")
        data = self.decompress(data, flow)
        data_integrity, integrity_reason = self.verify_data_integrity(flow, data)
        if not data_integrity:
            print(f"Data integrity failed {flow.request.pretty_url} {integrity_reason}")
            return
        should_save, reason = self.should_save_data(flow, data)
        # save data
        index_data = {
            "content-type": flow.response.headers.get("Content-Type", ""),
            "extension": self.guess_type(flow, data)
        }
        hashed = None
        if should_save:  # save regardless of cache control
            hashed = await self.cache_provider.set(data, index_data)

        should_cache, reason = self.should_cache(flow, data)
        if not should_cache:
            return

        if hashed is None:
            hashed = await self.cache_provider.set(data, index_data)

        metadata = await self.generate_or_pull_metadata(flow, data)

        hash_changed = metadata.get("data_hash", hashed) != hashed
        metadata["hash_changed_counter"] = metadata.get("hash_changed_counter", 0) + 1 if hash_changed else 0
        metadata["data_hash"] = hashed
        metadata["reason"] = reason
        metadata['last_modified'] = datetime.datetime.now().isoformat()
        await self.save_metadata(metadata)

    # check for gzip
    def decompress(self, data, flow):
        magic_bytes = data[:4]
        is_zipped = magic_bytes == b"\x1f\x8b\x08\x00"
        content_encoding = flow.response.headers.get("Content-Encoding", "")
        if content_encoding == "": return data
        print(f"Content encoding {content_encoding}")
        if content_encoding == "gzip" or is_zipped:
            try:
                data = gzip.decompress(data)
                flow.response.headers["Content-Encoding"] = "identity"
                flow.response.headers["Content-Length"] = str(len(data))
                flow.response.content = data
                print(f"Decompressed {flow.request.pretty_url}")
            except Exception as e:
                print(
                    f"Failed to decompress {flow.request.pretty_url} {e} {flow.response.headers.get('Content-Encoding', '')}")
                print(traceback.format_exc())
        return data

    def verify_data_integrity(self, flow: http.HTTPFlow, data: bytes) -> tuple[bool, str]:
        if data is None: return False, "Data is None"
        if flow.response is None: return False,  "Response is None"
        if flow.response.content is None: return False, "Response content is None"
        if flow.response.content != data: return False, "Data is not equal to response content"
        # check length
        if len(data) == 0: return False, "Data length is 0"
        if flow.response.headers.get("Content-Length", "") == "": return True, "Content length is unknown"
        if flow.response.headers.get("Content-Length", "") != str(len(data)): return False, f"Content length is not equal {flow.response.headers.get('Content-Length', '')} {len(data)}"
        return True, ""

    def should_refresh(self, metadata: Dict) -> tuple[bool, str]:
        chance = 0.1
        reason = ""
        # Check if volatile
        if metadata.get("hash_changed_counter", 0) > 0:
            chance = chance + 0.2
            reason = reason + f"Hash changed {metadata.get('hash_changed_counter', 0)} times "

        # Check last_modified
        if metadata['last_modified'] is None:
            reason = reason + f"Last modified is None "
            return True, reason
        last_modified = datetime.datetime.fromisoformat(metadata['last_modified'])
        if last_modified is None:
            reason = reason + f"Last modified is None "
            return True, reason
        day_since = (datetime.datetime.now() - last_modified).days
        if day_since > 7:
            chance = chance + 0.3
            reason = reason + f"Last modified {day_since} days ago "
        if day_since > 30:
            chance = chance + 0.3
            reason = reason + f"Last modified is too old "

        # Check if response header Expires
        expired = metadata["response"]["headers"].get("Expires", None)
        if expired is not None:
            if expired < datetime.datetime.now().isoformat():
                chance = chance + 0.3
                reason = reason + f"Expired {expired} "

        # Check if response header Cache-Control
        cache_control = metadata["response"]["headers"].get("Cache-Control", None)
        if cache_control is not None:
            if "no-cache" in cache_control or "no-store" in cache_control:
                chance = chance + 0.3
                reason = reason + f"Cache-Control {cache_control} "

        return random.random() < chance, reason + f"Chance {chance}"

    async def get_from_cache(self, flow: http.HTTPFlow) -> http.Response | None:
        metadata = await self.cache_provider.get_metadata(flow.request.pretty_url)
        if metadata is None: return None
        should_refresh, reason = self.should_refresh(metadata)
        print(f"Should refresh {should_refresh} {reason}")
        if should_refresh:
            return None

        data, index_data = await self.cache_provider.get(metadata["data_hash"])
        if data is None: return None
        # only necessary headers
        headers = {
            'Content-Type': metadata["response"]["headers"].get('content-type') or "",
            'Content-Disposition': metadata["response"]["headers"].get('content-disposition') or ""
        }
        # print(headers)
        return http.Response.make(
            status_code=200,
            content=data,
            headers=headers,
        )


cache_provider = cache.MongoCacheProvider()
cache_manager = CacheManager(cache_provider)


class CacheInterceptor:
    def __init__(self, that_cache_manager: CacheManager):
        self.cache_manager = that_cache_manager

    async def request(self, flow: http.HTTPFlow) -> None:
        start_time = time.time()
        # upgrade_header = flow.request.headers.get('Upgrade', '')
        # print(f"{flow.request.method} {flow.request.pretty_url}")
        if flow.request.method != "GET":
            return

        cached = await self.cache_manager.get_from_cache(flow)
        if cached is not None:
            print(f"Cache hit! {flow.request.pretty_url} Elapsed {time.time() - start_time}")
            cached.headers["Cached-By-Me"] = "very true"
            flow.response = cached
            print(f"Request Elapsed {time.time() - start_time}")

    async def response(self, flow: http.HTTPFlow) -> None:
        start_time = time.time()
        if flow.request.method != "GET": return
        cached_by_me = flow.response.headers.get("Cached-By-Me", "")
        if cached_by_me == "very true":
            # print("Very true")
            return
        await self.cache_manager.add_to_cache(flow)
        print(f"Response Elapsed {time.time() - start_time}")


addons = [
    CacheInterceptor(cache_manager)
]
