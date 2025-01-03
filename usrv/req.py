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
>>> # target public key is not the client public key
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

import os
import re
import ssl
import time
import json
import typing
import hashlib
import binascii
import traceback
import mimetypes

from usrv import LOG, DATA, dumpJson, secp256k1
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

OPENER = OpenerDirector()
OPENER.add_handler(HTTPHandler())
OPENER.add_handler(HTTPSHandler(context=CONTEXT))
OPENER.add_handler(FileHandler())

LATIN_1 = "latin-1"


class RequestBuilderException(Exception):
    pass


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


class FormData(list):
    """
    Implementation of multipart/form-data encoder.

    This class provides methods to construct, encode, and decode
    multipart/form-data content, as described in [RFC 7578](https://datatracke\
r.ietf.org/doc/html/rfc7578).
    """
    def append_json(self, name: str, value: dict = {}, **kwval) -> None:
        """
        Add a JSON object to the multipart body.

        Args:
            name (str): The name of the form field.
            value (dict, optional): A dictionary representing the JSON object.
                Defaults to None.
            kwval: Additional key-value pairs to include in the JSON object.

        Returns:
            typing.Any: The updated FormData instance.
        """
        list.append(self, {
            "name": name,
            "data": json.dumps(
                dict(value, **kwval), sort_keys=True, separators=(",", ":")
            ).encode(LATIN_1),
            "headers": {"Content-Type": "application/json"}
        })

    def append_value(
        self, name: str, value: typing.Union[str, bytes], **headers
    ) -> None:
        """
        Add a text or binary value to the multipart body.

        Args:
            name (str): The name of the form field.
            value (Union[str, bytes]): The value to add. Can be a string or
                bytes.
            headers: Additional headers to include for this field.
        """
        list.append(self, {
            "name": name,
            "data": value if isinstance(value, bytes) else (
                "%s" % value
            ).encode(LATIN_1),
            "headers": dict({"Content-Type": "text/plain"}, **headers)
        })

    def append_file(self, name: str, path: str) -> typing.Any:
        """
        Add a file to the multipart body.

        Args:
            name (str): The name of the form field.
            path (str): The path to the file to be added.

        Raises:
            IOError: If the file does not exist.
        """
        if os.path.isfile(path):
            list.append(self, {
                "name": name,
                "filename": os.path.basename(path),
                "headers": {
                    "Content-Type": (
                        mimetypes.guess_type(path)[0] or
                        "application/octet-stream"
                    )
                },
                "data": open(path, "rb").read()
            })
        else:
            raise IOError("file %s not found" % path)
        return self

    def dumps(self) -> str:
        """
        Encode the FormData instance as a multipart/form-data body.

        Returns:
            str: The encoded body and the corresponding Content-Type header.
        """
        body = b""
        boundary = binascii.hexlify(os.urandom(16))

        for value in [dict(v) for v in self]:
            field = value.pop("name").encode(LATIN_1)
            data = value.pop("data")
            headers = value.pop("headers")

            body += b'--' + boundary + b'\r\n'
            body += b'Content-Disposition: form-data; name="%s"; ' % field
            body += '; '.join(
                ['%s="%s"' % (n, v) for n, v in value.items()]
            ).encode(LATIN_1) + b'\r\n'
            body += (
                '\r\n'.join(
                    ['%s: %s' % (n, v) for n, v in headers.items()]
                ).encode(LATIN_1) + b"\r\n"
            ) or b'\r\n'
            body += b'\r\n' + data + b'\r\n'

        body += b'--' + boundary + b'--'
        return body, \
            f"multipart/form-data; boundary={boundary.decode('latin-1')}"

    def dump(self, folder: str = None) -> None:
        """
        Save the FormData instance to files in a directory.

        Each field in the FormData is written to a separate file.
        Additional metadata is saved as JSON.

        Returns:
            None
        """
        boundary = binascii.hexlify(os.urandom(16)).decode("utf-8")
        root_folder = folder or os.path.join(DATA, boundary)
        os.makedirs(root_folder, exist_ok=True)
        for elem in self:
            content_type = elem["headers"].get(
                "Content-Type", "application/octet-stream"
            )
            filename = elem.get("name", "undefined")
            ext = mimetypes.guess_extension(content_type) \
                or f".{content_type.replace('/', '.')}"
            with open(
                os.path.join(root_folder, f"{filename}{ext}"), "wb"
            ) as out:
                out.write(elem.get("data", b""))
            dumpJson(
                dict(
                    [k, v] for k, v in elem.items()
                    if k not in ["data", "name"]
                ), f"{filename}.values", root_folder
            )

    @staticmethod
    def encode(data: dict) -> str:
        """
        Encode a dictionary as a multipart/form-data string.

        Args:
            data (dict): The data to encode. Can include filepath, strings, or
                FormData instances.

        Returns:
            str: The encoded multipart/form-data string.
        """
        result = FormData()
        for name, value in data.items():
            if isinstance(value, FormData):
                result.extend(value)
            else:
                try:
                    result.append_file(name, value)
                except Exception:
                    if isinstance(value, dict):
                        result.append_json(name, value)
                    else:
                        result.append_value(name, value)
        return result.dumps()[0].decode(LATIN_1)

    @staticmethod
    def decode(data: str) -> typing.Any:
        """
        Decode a multipart/form-data string into a FormData instance.

        Args:
            data (str): The multipart/form-data string to decode.

        Returns:
            FormData: The decoded FormData instance.
        """
        result = FormData()
        boundary = re.match(".*(--[0-9a-f]+).*", data).groups()[0]

        frames = []
        # define frames by scanning lines
        for line in data.split("\r\n")[:-1]:
            if line == boundary:
                frames.append("")
            else:
                frames[-1] += line + "\r\n"

        for frame in frames:
            # separate lines to find void one (separator between info and data)
            splited = frame.split("\r\n")
            separator_index = splited.index("")
            # rebuild info and data
            info = "\r\n".join(splited[:separator_index])
            data = "\r\n".join(splited[separator_index+1:])
            # get all values from info
            values = dict(
                elem.replace('"', '').split("=")
                for elem in re.findall(r'([\w-]*[\s]*=[\s]*"[\S]*")', info)
            )
            # get headers from info
            headers = dict(
                elem.strip().replace(" ", "").split(":")
                for elem in re.findall(r'([\w-]*[\s]*:[\s]*[\S]*)', info)
            )
            headers.pop("Content-Disposition", False)
            # append item
            result.append(
                dict(
                    name=values.pop("name", "undefined"),
                    data=data.strip().encode(LATIN_1), headers=headers,
                    **values
                )
            )

        return result


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
        method: Callable = None
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

    def __call__(self, *args, **kwargs) -> typing.Any:
        """
        Executes the endpoint's method with provided arguments.

        Args:
            **kwargs: Parameters for the HTTP request.

        Returns:
            typing.Any: value returned by `method` attribute.
        """
        if len(args):
            path = f"{self.path}/{'/'.join(args)}"
        else:
            path = self.path
        return self.method(path, **kwargs)

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
        # TODO: update nonce
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
        data = data if isinstance(data, bytes) else data.encode(LATIN_1)

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
        http_input.decode(resp.headers.get_content_charset(LATIN_1)) \
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
                    http_req, url,
                    **dict({"_encoder": encoder or urlencode}, **parameters)
                ),
                timeout=timeout
            )
        )
    )


def identify(secret: str = None) -> None:
    global PRIVATE_KEY, PUBLIC_KEY
    PRIVATE_KEY, PUBLIC_KEY = secp256k1.generate_keypair(
        secret or secp256k1.load_secret()
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
