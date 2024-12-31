# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module is designed to handle common HTTP operations in a clean and
reusable manner, with dynamic endpoint resolution and robust response
management.

**Let's run a micro server:**

```python
# test.py
from usrv import route

# allow req.Endpoint.connect
@route.bind("/", methods=["HEAD"])
def base():
    return 200,

# public key endoint for encryption
@route.bind("/puk", methods=["GET"])
def puk():
    return 200, route.PUBLIC_KEY

@route.bind("/index")
def index(*args):
    return (200, ) + args

@route.bind("/api/endpoint", methods=["GET", "POST"])
def endpoit(a, b, **kwargs):
    method = kwargs["method"]
    if method == "POST":
        return 202, kwargs["data"]
    elif method == "GET":
        return 200, a, b
    else:
        return 404,

route.run(host='127.0.0.1', port=5000)
```

```bash
$ python path/to/test.py
INFO:usrv:listening on http://127.0.0.1:5000
CTRL+C to stop...
```

**Connect to a peer**

Remote path `/` allows HEAD request:

```python
>>> from usrv import req
>>> req.Endpoint.connect("http://127.0.0.1:5000")
200
```

Else, maunally set peer to `req.Endpoint` or use `_peer` keyword on each
request :

```python
>>> from usrv import req
>>> req.ENDPOINT.peer = "http://127.0.0.1:5000"
>>> # or
>>> req.GET.api.endpoint(_peer="http://127.0.0.1:5000")
>>> req.POST.api.endpoint(_peer="http://127.0.0.1:5000")
>>> # ...
```

**Endpoints**

```python
>>> # GET http://127.0.0.1:5000/puk
>>> req.GET.puk()
pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqB\
uFYcSmTQ==
>>> # GET http://127.0.0.1:5000/api/endpoints?a=12&b=test
>>> req.GET.api.endpoint(a=12, b="test")
["12", "test"]
>>> # POST data to http://127.0.0.1:5000/api/endpoints
>>> req.POST.api.endpoint(value1=1, value2=2)
'{"value1": 1, "value2": 2}'
```

**Encrypt HTTP body**

```python
>>> # encrypt only server body response
>>> req.POST.api.endpoint(
...   value1=1, value2=2, _headers={"Sender-Public-Key:req.PUBLIC_KEY}
... )
'{"value1": 1, "value2": 2}'
>>> # encrypt request and response bodies
>>> puk = req.GET.puk()
>>> puk
pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqB\
uFYcSmTQ==
>>> req.POST.api.endpoint(value1=1, value2=2, _puk=puk)
'{"value1": 1, "value2": 2}'
```

```python
>>> from usrv import secp256k1
>>> # generate a random keypair
>>> prk, puk = secp256k1.generate_keypair()
>>> # target public key is not server public key
>>> puk == req.GET.puk()
False
>>> print(req.POST.api.endpoints(value1=1, value2=2, _puk=puk))
<!DOCTYPE HTML>\n<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
    <h1>Error response</h1>
        <p>Error code: 500</p>
        <p>Message: Encryption error.</p>
        <p>Error code explanation: 5e234e6f68f30a056c2bd53e97b785e49895b1ae85d\
3cf323a95ot encrypted for public key pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhp\
a38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqBuFYcSmTQ==.</p>
    </body>
</html>
>>> req.POST.api.endpoint(
...   value1=1, value2=2, _headers={"Sender-Public-Key":puk}
... )
ERROR:usrv:Encryption error:
cc72124506d28ccb7bda70d6649f3f007bca1b8f1d829b047267ea543aa34c96ab39 not encry\
pted for public key pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYP\
GtOOyld7j6y0LP6i0aqBuFYcSmTQ==
'cc72124506d28ccb7bda70d6649f3f007bca1b8f1d829b047267ea543aa34c96ab39'
>>>
```
"""

import re
import ssl
import time
import json
import typing
import hashlib
import traceback

from usrv import LOG, secp256k1, FormData
from collections import OrderedDict
from collections.abc import Callable
from urllib.request import Request, OpenerDirector, HTTPHandler
from urllib.request import HTTPSHandler, FileHandler
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
from http.client import HTTPResponse
from collections import namedtuple

PRIVATE_KEY, PUBLIC_KEY = secp256k1.generate_keypair()

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
    "multipart/form-data": FormData.decode,
    "application/octet-stream": lambda o: o
}

ENCODERS = {
    urlencode: "application/x-www-form-urlencoded",
    json.dumps: "application/json",
    FormData.encode: "multipart/form-data"
}

OPENER = OpenerDirector()
OPENER.add_handler(HTTPHandler())
OPENER.add_handler(HTTPSHandler(context=CONTEXT))
OPENER.add_handler(FileHandler())


class RequestBuilderException(Exception):
    pass


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

    method = method.upper()
    encoder = kwargs.pop("_encoder", urlencode)
    peer = kwargs.pop("_peer", False) or Endpoint.peer
    headers = dict({"User-Agent": "Python/usrv"}, **kwargs.pop("_headers", {}))
    puk = kwargs.pop("_puk", None)

    if peer is None:
        raise RequestBuilderException("no peer to reach")

    if method in ["GET", "DELETE", "HEAD", "OPTION", "TRACE"]:
        query = urlencode(kwargs)
        data = None
    else:
        query = None
        data = encoder(kwargs)
        headers["Content-Type"] = ENCODERS.get(
            encoder, "application/octet-stream"
        )
        # get boundary value from data in cae of multipart/form-data
        if "multipart" in headers["Content-Type"]:
            boundary = re.match(".*--([0-9a-f]+).*", data).groups()[0]
            headers["Content-Type"] += f"; boundary={boundary}"
        if puk is not None:
            R, data = secp256k1.encrypt(puk, data)
            headers["Ephemeral-Public-Key"] = R
            headers["Sender-Public-Key"] = PUBLIC_KEY
            headers["Sender-Signature"] = secp256k1.sign(data+R, PRIVATE_KEY)
        data = data if isinstance(data, bytes) else data.encode("latin-1")

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
    content_type = resp.headers.get(
        "content-type", "application/octet-stream"
    ).lower()
    http_input = resp.read()
    http_input = \
        http_input.decode(resp.headers.get_content_charset("latin-1")) \
        if isinstance(http_input, bytes) else http_input
    # avoid json decoder error
    if "json" in content_type:
        http_input = http_input or 'null'

    puk = resp.headers.get("ephemeral-public-key", None)
    sender_puk = resp.headers.get("sender-public-key", None)
    signature = resp.headers.get("sender-signature", None)
    if all([puk, sender_puk, signature]) and secp256k1.verify(
        http_input+puk, signature, sender_puk
    ):
        decrypted = secp256k1.decrypt(PRIVATE_KEY, puk, http_input)
        if decrypted is False:
            LOG.error(
                "Encryption error:\n"
                f"{http_input} not encrypted for public key {PUBLIC_KEY}"
            )
            return http_input
        else:
            http_input = decrypted

    if "text/" not in content_type:
        http_input = DECODERS[content_type.split(";")[0].strip()](http_input)

    return http_input


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
            parsed_url = urlparse(peer)
            peer = f"{parsed_url.scheme}://{parsed_url.netloc}"
            res = OPENER.open(
                build_request("HEAD", _peer=peer), timeout=Endpoint.timeout
            )
        except Exception as error:
            LOG.error("%r\n%s", error, traceback.format_exc())
        else:
            Endpoint.peer = peer
            return res.status
        return False


def build_endpoint(
    http_req: str = "GET", encoder: Callable = json.dumps,
    timeout: int = Endpoint.timeout
) -> Endpoint:
    """
    Creates a root endpoint.

    Args:
        http_req (str): Name of HTTP method (i.e. HEAD, GET, POST etc...).
        encoder (Callable): Data encoder function to use. (defaults to json)
        timeout (int): Request timeout in seconds.

    Returns:
        Endpoint: Root endpoint.
    """
    return Endpoint(
        method=lambda url, **parameters: manage_response(
            OPENER.open(
                build_request(
                    http_req, url, _encoder=encoder or urlencode, **parameters
                ),
                timeout=timeout
            )
        )
    )


# build json endpoints (ie HTTP body will be encoded as JSON)
CONNECT = build_endpoint("CONNECT")
GET = build_endpoint("GET")
HEAD = build_endpoint("HEAD")
OPTION = build_endpoint("OPTION")
PATCH = build_endpoint("PATCH")
POST = build_endpoint("POST")
PUT = build_endpoint("PUT")
TRACE = build_endpoint("TRACE")
DELETE = build_endpoint("DELETE")
CONNECT = build_endpoint("CONNECT")
