<a id="usrv.req"></a>

# req

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
pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqBuFYcSmTQ==
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
pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqBuFYcSmTQ==
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
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
    <h1>Error response</h1>
        <p>Error code: 500</p>
        <p>Message: Encryption error.</p>
        <p>Error code explanation: 5e234e6f68f30a056c2bd53e97b785e49895b1ae85d3cf323a95ot encrypted for public key pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqBuFYcSmTQ==.</p>
    </body>
</html>
>>> # target public key is not the client public key
>>> req.POST.api.endpoint(
...   value1=1, value2=2, _headers={"Sender-Public-Key":puk}
... )
ERROR:usrv:Encryption error:
cc72124506d28ccb7bda70d6649f3f007bca1b8f1d829b047267ea543aa34c96ab39 not encrypted for public key pP15aGDcFoqGTHTReiIfEvUcQ2c3AQjYcgCeLgKhpa38Rsub69i6RifuYPGtOOyld7j6y0LP6i0aqBuFYcSmTQ==
'cc72124506d28ccb7bda70d6649f3f007bca1b8f1d829b047267ea543aa34c96ab39'
>>>
```

<a id="usrv.req.RequestCache"></a>

## RequestCache Objects

```python
class RequestCache()
```

Cache manager for HTTP Request objects.

<a id="usrv.req.RequestCache.__init__"></a>

### RequestCache.\_\_init\_\_

```python
def __init__(max_size: int = 100, ttl: int = 300)
```

Initialize the cache.

**Arguments**:

- `max_size` _int_ - Maximum number of entries in the cache.
- `ttl` _int_ - Time-to-live for cache entries in seconds.

<a id="usrv.req.RequestCache.generate_key"></a>

### RequestCache.generate\_key

```python
@staticmethod
def generate_key(method: str, path: str, **kwargs) -> str
```

Generate a unique cache key for a request.

<a id="usrv.req.RequestCache.get"></a>

### RequestCache.get

```python
def get(key: str) -> typing.Union[None, typing.Tuple[int, Request]]
```

Retrieve an entry from the cache.

<a id="usrv.req.RequestCache.set"></a>

### RequestCache.set

```python
def set(key: str, request: Request) -> None
```

Add an entry to the cache.

<a id="usrv.req.FormData"></a>

## FormData Objects

```python
class FormData(list)
```

Implementation of multipart/form-data encoder.

This class provides methods to construct, encode, and decode
multipart/form-data content, as described in [RFC 7578](https://datatracker.ietf.org/doc/html/rfc7578).

<a id="usrv.req.FormData.append_json"></a>

### FormData.append\_json

```python
def append_json(name: str, value: dict = {}, **kwval) -> None
```

Add a JSON object to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `value` _dict, optional_ - A dictionary representing the JSON object.
  Defaults to None.
- `kwval` - Additional key-value pairs to include in the JSON object.
  

**Returns**:

- `typing.Any` - The updated FormData instance.

<a id="usrv.req.FormData.append_value"></a>

### FormData.append\_value

```python
def append_value(name: str, value: typing.Union[str, bytes],
                 **headers) -> None
```

Add a text or binary value to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `value` _Union[str, bytes]_ - The value to add. Can be a string or
  bytes.
- `headers` - Additional headers to include for this field.

<a id="usrv.req.FormData.append_file"></a>

### FormData.append\_file

```python
def append_file(name: str, path: str) -> typing.Any
```

Add a file to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `path` _str_ - The path to the file to be added.
  

**Raises**:

- `IOError` - If the file does not exist.

<a id="usrv.req.FormData.dumps"></a>

### FormData.dumps

```python
def dumps() -> str
```

Encode the FormData instance as a multipart/form-data body.

**Returns**:

- `str` - The encoded body and the corresponding Content-Type header.

<a id="usrv.req.FormData.dump"></a>

### FormData.dump

```python
def dump(folder: str = None) -> None
```

Save the FormData instance to files in a directory.

Each field in the FormData is written to a separate file.
Additional metadata is saved as JSON.

**Returns**:

  None

<a id="usrv.req.FormData.encode"></a>

### FormData.encode

```python
@staticmethod
def encode(data: dict) -> str
```

Encode a dictionary as a multipart/form-data string.

**Arguments**:

- `data` _dict_ - The data to encode. Can include filepath, strings, or
  FormData instances.
  

**Returns**:

- `str` - The encoded multipart/form-data string.

<a id="usrv.req.FormData.decode"></a>

### FormData.decode

```python
@staticmethod
def decode(data: str) -> typing.Any
```

Decode a multipart/form-data string into a FormData instance.

**Arguments**:

- `data` _str_ - The multipart/form-data string to decode.
  

**Returns**:

- `FormData` - The decoded FormData instance.

<a id="usrv.req.Endpoint"></a>

## Endpoint Objects

```python
class Endpoint()
```

Represents an HTTP endpoint with dynamic attribute handling.

**Attributes**:

- `startswith_` _re.Pattern_ - Pattern to match internal attributes.
- `timeout` _int_ - Default timeout for requests.
- `opener` _OpenerDirector_ - Opener to handle HTTP requests.
- `peer` _str_ - Base URL for the endpoint.

<a id="usrv.req.Endpoint.__init__"></a>

### Endpoint.\_\_init\_\_

```python
def __init__(master: typing.Any = None,
             name: str = "",
             method: Callable = None) -> None
```

Initializes an Endpoint instance.

**Arguments**:

- `master` _typing.Any_ - Parent endpoint.
- `name` _str_ - Name of the current endpoint.
- `method` _Callable_ - Request-building method.

<a id="usrv.req.Endpoint.__getattr__"></a>

### Endpoint.\_\_getattr\_\_

```python
def __getattr__(attr: str) -> typing.Any
```

Dynamically resolves sub-endpoints.

**Arguments**:

- `attr` _str_ - Attribute name.
  

**Returns**:

- `Endpoint` - New sub-endpoint instance.

<a id="usrv.req.Endpoint.__call__"></a>

### Endpoint.\_\_call\_\_

```python
def __call__(*args, **kwargs) -> typing.Any
```

Executes the endpoint's method with provided arguments.

**Arguments**:

- `**kwargs` - Parameters for the HTTP request.
  

**Returns**:

- `typing.Any` - value returned by `method` attribute.

<a id="usrv.req.Endpoint.connect"></a>

### Endpoint.connect

```python
@staticmethod
def connect(peer: str) -> typing.Union[int, bool]
```

Tests connection to a peer endpoint and store it if success.

**Arguments**:

- `peer` _str_ - Peer URL to test.
  

**Returns**:

  typing.Union[int, bool]: HTTP status code or False on failure.

<a id="usrv.req.build_request"></a>

## build\_request

```python
def build_request(method: str = "GET", path: str = "/", **kwargs) -> Request
```

Builds an HTTP request object.

**Arguments**:

- `method` _str_ - HTTP method (e.g., 'GET', 'POST'). Defaults to 'GET'.
- `path` _str_ - URL path for the request. Defaults to '/'.
- `**kwargs` - Additional keyword arguments for query parameters, headers,
  and data.
  

**Returns**:

- `Request` - Configured HTTP request object.

<a id="usrv.req.manage_response"></a>

## manage\_response

```python
def manage_response(resp: HTTPResponse) -> typing.Union[dict, str]
```

Parses the HTTP response.

**Arguments**:

- `resp` _HTTPResponse_ - HTTP response object.
  

**Returns**:

  typing.Union[dict, str]: Decoded response content.

<a id="usrv.req.build_endpoint"></a>

## build\_endpoint

```python
def build_endpoint(http_req: str = "GET",
                   encoder: Callable = json.dumps,
                   timeout: int = Endpoint.timeout) -> Endpoint
```

Creates a root endpoint.

**Arguments**:

- `http_req` _str_ - Name of HTTP method (i.e. HEAD, GET, POST etc...).
- `encoder` _Callable_ - Data encoder function to use. (defaults to json)
- `timeout` _int_ - Request timeout in seconds.
  

**Returns**:

- `Endpoint` - Root endpoint.

