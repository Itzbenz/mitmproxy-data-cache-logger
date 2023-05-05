import datetime
import gzip
import json
import logging
import mimetypes
import os
import random
import time
from typing import Dict

import magic
import mitmproxy
from dotenv import load_dotenv
from mitmproxy import http

import cache

load_dotenv()
cache_logger = logging.getLogger("CacheManager")
cache_logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))
cache_logger.warning("Log level is %s", logging.getLevelName(cache_logger.level))

STRIP_CACHE_HEADERS = os.getenv("STRIP_CACHE_HEADERS", "true").lower() == "true"
cache_logger.warning("Strip cache headers is %s", STRIP_CACHE_HEADERS)

analytics_logger = logging.getLogger("Analytics")
analytics_logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))


# Mime, Extension
def guess_magic_bytes(magic_bytes: bytes) -> tuple[str, str]:
    new_guess = magic.from_buffer(magic_bytes, mime=True).strip()
    new_ext = mimetypes.guess_extension(new_guess, strict=False)
    cache_logger.debug("Guessing %s as %s", magic_bytes, new_guess)
    return new_guess, new_ext


def try_strip_cache_header(headers: mitmproxy.http.Headers):
    logging.debug(f"{STRIP_CACHE_HEADERS} {headers}")
    if not STRIP_CACHE_HEADERS or not headers: return
    headers.pop("Cache-Control", None)
    headers.pop("cache-control", None)
    headers.pop("Expires", None)
    headers.pop("expires", None)
    headers.pop("Pragma", None)
    headers.pop("pragma", None)
    headers.pop("Age", None)
    headers.pop("age", None)
    headers.pop("Warning", None)
    headers.pop("warning", None)
    headers.pop("Last-Modified", None)
    headers.pop("last-modified", None)
    headers.pop("ETag", None)
    headers.pop("etag", None)
    logging.debug(f"Stripped Cache Headers {headers}")


# noinspection PyMethodMayBeStatic
class CacheManager:
    def __init__(self, that_cache_provider: cache.AbstractCacheProvider):
        self.cache_provider = that_cache_provider

    # doesn't adhere to cache control only care about the content
    def should_save_data(self, flow: http.HTTPFlow, data: bytes):
        content_type = flow.response.headers.get("Content-Type", "")
        mime, file_ext = guess_magic_bytes(data)
        reason = ""
        is_media = lambda x: "image" in x or "video" in x or "audio" in x
        if content_type != "" and mime not in content_type:
            if is_media(content_type) or is_media(mime):
                cache_logger.warning(flow.request.pretty_url)
                cache_logger.warning(f"Content type {content_type} != {mime}")
        cache_logger.debug(f"Content type {content_type} Magic: {mime} {file_ext}")
        if mime is None or mime == "":
            mime = content_type
        if is_media(mime):
            reason = reason + f"Mime is {mime} "
        if is_media(content_type):
            reason = reason + f"Content is {content_type} "
        # if file_ext != ".bin":
        #    reason = reason + f"File extension {file_ext}"
        reason = reason.strip()
        return "" != reason, reason

    # Extended version, onl

    # adhere to cache control
    def should_cache(self, flow: http.HTTPFlow, data: bytes):
        should, reason = self.should_save_data(flow, data)
        reason = reason + " "
        cache_control = flow.response.headers.get("Cache-Control", "")
        content_type = flow.response.headers.get("Content-Type", "")
        should_cache_by_header = True

        if cache_control.strip() == "":
            # check if html
            if content_type is not None and "text/html" in content_type:
                # should_cache_by_header = False
                reason = reason + f"Content type {content_type} "
                # set expire header if not set
                if flow.response.headers.get("Expires", "") == "":
                    # RFC 2616
                    flow.response.headers["Expires"] = (
                                datetime.datetime.utcnow() + datetime.timedelta(minutes=2)).strftime(
                        "%a, %d %b %Y %H:%M:%S GMT")

            should_cache_by_header = False
        if "no-cache" in cache_control:
            should_cache_by_header = False
        if "private" in cache_control:
            should_cache_by_header = False
        if "no-store" in cache_control:
            should_cache_by_header = False
        if "must-revalidate" in cache_control:
            should_cache_by_header = False
        if "max-age=0" in cache_control:
            should_cache_by_header = False

        # if content type is image or file_ext isn't bin then save file
        if should_cache_by_header:
            reason = reason + f"Cache Control {cache_control} "
        # trim
        reason = reason.strip()
        should = "" != reason
        if should:
            cache_logger.info(f"Caching {flow.request.pretty_url} because {reason}")
        else:
            cache_logger.debug(
                f"Potential caching {flow.request.method} {flow.request.pretty_url} {content_type} {cache_control}")
        return should, reason

    def generate_metadata(self, flow: http.HTTPFlow, data: bytes | None) -> Dict:
        metadata = {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "headers": flow.request.headers,
            "hits": 0,
            "response": {
                "http_version": flow.response.http_version,
                "headers": flow.response.headers,
                "status_code": flow.response.status_code,
            }
        }
        if data is not None:
            mime, file_ext = guess_magic_bytes(data)
            metadata["extension"] = file_ext
            metadata["mime"] = mime
            metadata["size"] = len(data)
        return metadata

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
            cache_logger.info(f"Data is None {flow.request.pretty_url}")
            return
        # check if compression is enabled
        # logger.debug(f"length {len(data)}")
        data = self.decompress(data, flow)
        data_integrity, integrity_reason = self.verify_data_integrity(flow, data)
        if not data_integrity:
            cache_logger.warning(f"Data integrity failed {flow.request.pretty_url} {integrity_reason}")
            return
        should_save, reason = self.should_save_data(flow, data)
        # save data
        index_data = {
            "content-type": flow.response.headers.get("Content-Type", ""),
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
        metadata['last_accessed'] = metadata['last_modified']
        await self.save_metadata(metadata)
        try_strip_cache_header(flow.response.headers)

    # check for gzip
    def decompress(self, data, flow):
        magic_bytes = data[:4]

        is_zipped = magic_bytes == b"\x1f\x8b\x08\x00"
        content_encoding = flow.response.headers.get("Content-Encoding", "")

        if content_encoding == "": return data
        if content_encoding == "gzip" and is_zipped:
            try:
                data = gzip.decompress(data)

                cache_logger.info(f"Decompressed {flow.request.pretty_url}")
            except Exception as e:
                cache_logger.error(
                    f"Failed to decompress {flow.request.pretty_url} {e} {flow.response.headers.get('Content-Encoding', '')}",
                    exc_info=True)
        del flow.response.headers["Content-Encoding"]
        flow.response.headers["content-length"] = str(len(data))
        flow.response.content = data
        return data

    def verify_data_integrity(self, flow: http.HTTPFlow, data: bytes) -> tuple[bool, str]:
        if data is None: return False, "Data is None"
        if flow.response is None: return False, "Response is None"
        if flow.response.content is None: return False, "Response content is None"
        if flow.response.content != data: return False, "Data is not equal to response content"
        # check length
        if len(data) == 0: return False, "Data length is 0"
        if flow.response.headers.get("Content-Length", "") == "": return True, "Content length is unknown"
        if flow.response.headers.get("Content-Length", "") != str(
                len(data)): return False, f"Content length is not equal {flow.response.headers.get('Content-Length', '')} {len(data)}"
        return True, ""

    def should_refresh(self, metadata: Dict) -> tuple[bool, str]:
        chance = 0.1
        reason = "Base chance"
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
            # RFC 2616
            if datetime.datetime.strptime(expired, "%a, %d %b %Y %H:%M:%S %Z") < datetime.datetime.now():
                chance = chance + 0.3
                # calculate seconds since
                seconds = (datetime.datetime.now() - datetime.datetime.strptime(expired,
                                                                                "%a, %d %b %Y %H:%M:%S %Z")).seconds
                reason = reason + f"Expired since {seconds} seconds ago "

                # Check if response header Cache-Control
        cache_control = metadata["response"]["headers"].get("Cache-Control", None)
        if cache_control is not None:
            if "no-cache" in cache_control or "no-store" in cache_control:
                chance = chance + 0.3
                reason = reason + f"Cache-Control {cache_control} "

        return random.random() < chance, reason + f" Chance {chance}"

    async def get_from_cache(self, flow: http.HTTPFlow) -> http.Response | None:
        metadata = await self.cache_provider.get_metadata(flow.request.pretty_url)
        if metadata is None: return None
        should_refresh, reason = self.should_refresh(metadata)
        if should_refresh:
            cache_logger.info(f"Refreshing {flow.request.pretty_url} {reason}")
            return None
        else:
            cache_logger.debug(f"Should refresh {should_refresh} {reason}")

        data, index_data = await self.cache_provider.get(metadata["data_hash"])
        if data is None: return None
        # Increment hits
        metadata["hits"] = metadata.get("hits", 0) + 1
        metadata['last_accessed'] = datetime.datetime.now().isoformat()
        await self.save_metadata(metadata)
        # only necessary headers
        headers = {}
        headers['Content-Length'] = str(len(data))
        headers["Cached-By-Me"] = "very true"
        headers["Cache-Control"] = "no-store"
        if metadata["response"]["headers"].get("content-encoding", "") != "":
            headers['Content-Encoding'] = metadata["response"]["headers"].get("content-encoding", "")
        if metadata["response"]["headers"].get("content-type", "") != "":
            headers['Content-Type'] = metadata["response"]["headers"].get("content-type", "")

        # Add access control headers if present
        for header in metadata["response"]["headers"]:
            if header.lower().startswith("access-control"):
                headers[header] = metadata["response"]["headers"][header]

        return http.Response.make(
            status_code=200,
            content=data,
            headers=headers,
        )


cache_provider = None
cache_provider_str = g = os.environ.get("CACHE_PROVIDER", "mongodb")
if cache_provider_str == "mongodb":
    cache_provider = cache.MongoCacheProvider()
elif cache_provider_str == "file":
    cache_provider = cache.FileCacheProvider()
else:
    raise Exception(f"Unknown cache provider {cache_provider_str}")

cache_manager = CacheManager(cache_provider)


class CacheInterceptor:
    def __init__(self, that_cache_manager: CacheManager):
        self.cache_manager = that_cache_manager

    async def request(self, flow: http.HTTPFlow) -> None:
        start_time = time.time()
        if flow.request.method != "GET":
            return
        flow.intercept()
        cached = await self.cache_manager.get_from_cache(flow)
        if cached is not None:
            cache_logger.info(f"Cache hit! {flow.request.pretty_url} Elapsed {time.time() - start_time}")
            cached.headers["Cached-By-Me"] = "very true"
            flow.response = cached
            cache_logger.debug(f"Request Elapsed {time.time() - start_time}")
        flow.resume()

    async def response(self, flow: http.HTTPFlow) -> None:
        start_time = time.time()
        if flow.request.method != "GET": return
        cached_by_me = flow.response.headers.get("Cached-By-Me", "")
        if cached_by_me == "very true":
            return
        await self.cache_manager.add_to_cache(flow)
        cache_logger.debug(f"Response Elapsed {time.time() - start_time}")


randomURL = f"analytics-wwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"


# noinspection PyMethodMayBeStatic
class AnalyticsInterceptor:

    async def response(self, flow: http.HTTPFlow) -> None:
        # Hijack HTML
        if "text/html" not in flow.response.headers.get("Content-Type", ""): return
        if flow.response.text is None: return

        # Inject script
        script = None
        with open("analytics.js", "r") as f:
            script = f.read()
        if script is None: return
        script = script.replace("{{URL}}", flow.request.pretty_url)
        script = script.replace("{{analyticsServerURL}}", randomURL + "/" + str(random.randint(0, 1000000000000)))
        # check if have head
        if "<head>" not in flow.response.text:
            # inject anyway
            flow.response.text = flow.response.text + f"<script>{script}</script>"
        else:
            flow.response.text = flow.response.text.replace("</head>",
                                                            f"<script>{script}</script></head>")
        bites = flow.response.text.encode("utf-8")
        flow.response.headers["Content-Length"] = str(len(bites))
        flow.response.headers["Content-Type"] = "text/html"
        flow.response.content = bites
        try_strip_cache_header(flow.response.headers)
        analytics_logger.info(f"Analytics script injected {flow.request.pretty_url}")

    def request(self, flow: http.HTTPFlow) -> None:
        if randomURL not in flow.request.pretty_url: return

        analytics_logger.info(f"[{flow.request.method}] {flow.request.pretty_url}")
        if flow.request.text is None: return
        flow.intercept()
        analytics_logger.info(f"Analytics request intercepted {flow.request.pretty_url}")
        analytics_logger.info(flow.request.text)

        flow.response = http.Response.make(
            status_code=200,
            content=json.dumps({"status": "ok"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        flow.response.headers["Content-Length"] = str(len(flow.response.content))

        flow.resume()


def scrub_quic_headers(headers: mitmproxy.http.Headers) -> None:
    if "h3" in headers.get("Upgrade", ""):
        headers.pop("Upgrade")
    if "h3" in headers.get("Alt-Svc", ""):
        arrays = headers.get_all("Alt-Svc")
        for array in arrays:
            if "h3" in array:
                arrays.remove(array)
        headers.set_all("Alt-Svc", arrays)


# noinspection PyMethodMayBeStatic
class AntiQuic:
    def udp_start(self, flow: mitmproxy.udp.UDPFlow) -> None:
        print(f"UDP {flow.server_conn.address}")
        if flow.server_conn.address[1] == 443 or flow.server_conn.address[1] == 80:
            flow.kill()

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        scrub_quic_headers(flow.request.headers)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        scrub_quic_headers(flow.response.headers)


addons = [
    CacheInterceptor(cache_manager),
    # AnalyticsInterceptor(),
    AntiQuic()
]
