<a id="usrv.req"></a>

# req

__HTTP Client Module__


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
[{'accept-encoding': 'identity', 'host': '127.0.0.1:5000', 'user-agent': 'Python/usrv', 'content-type': 'application/json', 'connection': 'close'}, None]
>>> req.GET.api.endpoint()
[None, None, {'headers': {'accept-encoding': 'identity', 'host': '127.0.0.1:5000', 'user-agent': 'Python/usrv', 'content-type': 'application/json', 'connection': 'close'}, 'data': None}]
```

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
             method: Callable = manage_response) -> None
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
def __call__(**kwargs) -> typing.Any
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

