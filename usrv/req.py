# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
# HTTP Client Module

This module provides a flexible and extensible framework for building, sending,
and managing HTTP requests and responses. It includes support for dynamic
endpoints, SSL configuration, and content decoding based on MIME types.

## Classes
  - RequestCache: a caching service for python HTTP Request.
  - Endpoint: Represents an HTTP endpoint with dynamic attribute handling and
    customizable request methods.

## Functions
  - build_request: Constructs HTTP requests with specified parameters and
    headers.
  - manage_response: Parses and decodes HTTP responses based on their MIME
    types.

## Constants
  - CONTEXT: SSL context with disabled hostname verification.
  - DECODERS: Dictionary mapping MIME types to their respective parsers.
  - OPENER: Global HTTP request opener.

## Endpoints
Predefined instances of the `Endpoint` class for standard HTTP methods:
  - CONNECT
  - GET
  - HEAD
  - OPTION
  - PATCH
  - POST
  - PUT
  - TRACE
  - DELETE

This module is designed to handle common HTTP operations in a clean and
reusable manner, with dynamic endpoint resolution and robust response
management.

**Let's run a micro server:**

```python
from usrv import route

# allow req.Endpoint.connect
@route.bind("/", methods=["HEAD"])
def base():
    return 200,

@route.bind("/index")
def index(*args):
    return (200, ) + args

@route.bind("/api/endpoint", methods=["GET", "POST"])
def endpoit(a, b, **kwargs):
    method = kwargs["method"]
    if method == "POST":
        return 202,
    elif method == "GET":
        return 200, a, b, kwargs
    else:
        return 404,

route.run(host='127.0.0.1', port=5000)
```

**execute simple requests:**

```python
>>> from usrv import req
>>> req.Endpoint.connect("http://127.0.0.1:5000")
200
>>> req.GET.index()
[{'accept-encoding': 'identity', 'host': '127.0.0.1:5000', 'user-agent': 'Pyth\
on/usrv', 'content-type': 'application/json', 'connection': 'close'}, None]
>>> req.GET.api.endpoint()
[None, None, {'headers': {'accept-encoding': 'identity', 'host': '127.0.0.1:50\
00', 'user-agent': 'Python/usrv', 'content-type': 'application/json', 'connect\
ion': 'close'}, 'data': None}]
>>> req.POST.api.endpoint()
[]
```
"""

import re
import ssl
import time
import json
import typing
import hashlib
import traceback

from usrv import LOG
from collections import OrderedDict
from collections.abc import Callable
from urllib.request import Request, OpenerDirector, HTTPHandler
from urllib.request import HTTPSHandler, FileHandler
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
from http.client import HTTPResponse
from collections import namedtuple

# namedtuple to match the internal signature of urlunparse
Urltuple = namedtuple(
    typename='Urltuple', field_names=[
        'scheme', 'netloc', 'path', 'params', 'query', 'fragment'
    ]
)

CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = True
CONTEXT.verify_mode = ssl.CERT_REQUIRED
# Disable outdated SSL and TLS lib
CONTEXT.options |= ssl.OP_NO_SSLv2
CONTEXT.options |= ssl.OP_NO_SSLv3
CONTEXT.options |= ssl.OP_NO_TLSv1
CONTEXT.options |= ssl.OP_NO_TLSv1_1

DECODERS = {
    "application/x-www-form-urlencoded": parse_qsl,
    "application/json": json.loads,
    "application/octet-stream": lambda o: o
}

ENCODERS = {
    urlencode: "application/x-www-form-urlencoded",
    json.dumps: "application/json",
}

OPENER = OpenerDirector()
OPENER.add_handler(HTTPHandler())
OPENER.add_handler(HTTPSHandler(context=CONTEXT))
OPENER.add_handler(FileHandler())


def build_request(method: str = "GET", path: str = "/", **kwargs) -> Request:
    """
    Builds an HTTP request object.

    Args:
        method (str): HTTP method (e.g., 'GET', 'POST'). Defaults to 'GET'.
        path (str): URL path for the request. Defaults to '/'.
        **kwargs: Additional keyword arguments for query parameters, headers,
            and data.

    Returns:
        Request: Configured HTTP request object.
        """
    # Check if the request is already cached
    key = RequestCache.generate_key(method, path, **kwargs)
    cached_request = Endpoint.cache.get(key)
    if cached_request is not None:
        return cached_request

    encoder = kwargs.pop("encoder", urlencode)
    peer = kwargs.pop("peer", False) or Endpoint.peer
    headers = kwargs.pop("headers", {"User-Agent": "Python/usrv"})
    method = method.upper()

    if method in ["GET", "DELETE", "HEAD", "OPTION", "TRACE"]:
        query = urlencode(kwargs)
        data = None
    else:
        query = None
        data = encoder(kwargs)
        data = data if isinstance(data, bytes) else data.encode("latin-1")

    headers["Content-Type"] = ENCODERS.get(encoder, "application/octet-stream")
    req = Request(
        urlunparse(urlparse(peer)._replace(path=path, query=query)),
        data, headers
    )
    req.get_method = lambda: method
    Endpoint.cache.set(key, req)
    return req


def manage_response(resp: HTTPResponse) -> typing.Union[dict, str]:
    """
    Parses the HTTP response.

    Args:
        resp (HTTPResponse): HTTP response object.

    Returns:
        typing.Union[dict, str]: Decoded response content.
    """
    content_type = resp.headers.get("content-type").lower()
    text = resp.read()
    text = text.decode(resp.headers.get_content_charset("latin-1")) \
        if isinstance(text, bytes) else text

    if "text/" not in content_type:
        text = DECODERS[content_type.split(";")[0].strip()](text)

    return text


class RequestCache:
    """Cache manager for HTTP Request objects."""

    def __init__(self, max_size: int = 100, ttl: int = 300):
        """
        Initialize the cache.

        Args:
            max_size (int): Maximum number of entries in the cache.
            ttl (int): Time-to-live for cache entries in seconds.
        """
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl

    @staticmethod
    def generate_key(method: str, path: str, **kwargs) -> str:
        """Generate a unique cache key for a request."""
        return hashlib.sha256(
            f"{method.upper()}|{path}|{sorted(kwargs.items())}".encode("utf-8")
        ).hexdigest()

    def get(self, key: str) -> typing.Union[None, typing.Tuple[int, Request]]:
        """Retrieve an entry from the cache."""
        entry = self.cache.get(key)
        if entry is not None:
            timestamp, request = entry
            if time.time() - timestamp > self.ttl:
                # Entry has expired
                self.cache.pop(key)
            return request
        return None

    def set(self, key: str, request: Request) -> None:
        """Add an entry to the cache."""
        if len(self.cache) >= self.max_size:
            # Remove the oldest entry
            self.cache.popitem(last=False)
        self.cache[key] = (time.time(), request)


class Endpoint:
    """
    Represents an HTTP endpoint with dynamic attribute handling.

    Attributes:
        startswith_ (re.Pattern): Pattern to match internal attributes.
        timeout (int): Default timeout for requests.
        opener (OpenerDirector): Opener to handle HTTP requests.
        peer (str): Base URL for the endpoint.
    """

    cache = RequestCache(100, 600)
    startswith_ = re.compile(r"^_[0-9].*")
    timeout = 5.0
    opener = None
    peer = None

    def __init__(
        self, master: typing.Any = None, name: str = "",
        method: Callable = manage_response
    ) -> None:
        """
        Initializes an Endpoint instance.

        Args:
            master (typing.Any): Parent endpoint.
            name (str): Name of the current endpoint.
            method (Callable): Request-building method.
        """
        if master is None:
            self.path = name
        else:
            self.path = f"{master.path}/{name}"
        self.method = method

    def __getattr__(self, attr: str) -> typing.Any:
        """
        Dynamically resolves sub-endpoints.

        Args:
            attr (str): Attribute name.

        Returns:
            Endpoint: New sub-endpoint instance.
        """
        try:
            return Endpoint.__getattribute__(self, attr)
        except AttributeError:
            if Endpoint.startswith_.match(attr):
                attr = attr[1:]
            return Endpoint(self, attr, self.method)

    def __call__(self, **kwargs) -> typing.Any:
        """
        Executes the endpoint's method with provided arguments.

        Args:
            **kwargs: Parameters for the HTTP request.

        Returns:
            typing.Any: value returned by `method` attribute.
        """
        return self.method(self.path, **kwargs)

    @staticmethod
    def connect(peer: str) -> typing.Union[int, bool]:
        """
        Tests connection to a peer endpoint and store it if success.

        Args:
            peer (str): Peer URL to test.

        Returns:
            typing.Union[int, bool]: HTTP status code or False on failure.
        """
        try:
            res = OPENER.open(
                build_request("HEAD", peer=peer), timeout=Endpoint.timeout
            )
        except Exception as error:
            LOG.error("%r\n%s", error, traceback.format_exc())
        else:
            Endpoint.peer = peer
            return res.status
        return False


# HTTP method root endpoints
CONNECT = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("CONNECT", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

GET = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("GET", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

HEAD = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("HEAD", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

OPTION = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("OPTION", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

PATCH = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("PATCH", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

POST = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("POST", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

PUT = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("PUT", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

TRACE = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("TRACE", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)

DELETE = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("DELETE", url, encoder=json.dumps, **parameters),
            timeout=Endpoint.timeout
        )
    )
)
