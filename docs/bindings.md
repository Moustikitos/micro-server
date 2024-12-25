<a id="usrv.route"></a>

# route

This module contains all the utilities to launch a micro server from python
lib. It is not recommended to use it in production mode.

```bash
$ python route.py -h
Usage: route.py [options] BINDINGS...

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -t THREADS, --threads=THREADS
                        set thread number           [default: 2]
  -l LOGLEVEL, --log-level=LOGLEVEL
                        set log level from 1 to 100 [default: 20]
  -i HOST, --ip=HOST    ip to run from              [default: 127.0.0.1]
  -p PORT, --port=PORT  port to use                 [default: 5000]
```

`BINDINGS` is a list of python modules containing python bound functions.

<a id="usrv.route.Endpoint"></a>

## Endpoint Objects

```python
class Endpoint()
```

Placeholder for storing endpoint mappings.

<a id="usrv.route.EndpointAlreadyDefined"></a>

## EndpointAlreadyDefined Objects

```python
class EndpointAlreadyDefined(Exception)
```

Exception raised when an endpoint is already defined.

<a id="usrv.route.UrlMatchError"></a>

## UrlMatchError Objects

```python
class UrlMatchError(Exception)
```

Exception raised for errors in URL pattern matching.

<a id="usrv.route.uHTTPRequestHandler"></a>

## uHTTPRequestHandler Objects

```python
class uHTTPRequestHandler(BaseHTTPRequestHandler)
```

Custom HTTP request handler that handles HTTP methods dynamically.

**Methods**:

- `format_response` - Formats the response as JSON.
- `do_` - Processes HTTP requests based on registered endpoints.

<a id="usrv.route.uHTTPRequestHandler.__getattr__"></a>

### uHTTPRequestHandler.\_\_getattr\_\_

```python
def __getattr__(attr: str) -> Callable
```

Dynamically handles HTTP methods like 'do_GET', 'do_POST', etc.

**Arguments**:

- `attr` _str_ - The attribute name.
  

**Returns**:

- `Callable` - The dynamic handler function.

<a id="usrv.route.uHTTPRequestHandler.format_response"></a>

### uHTTPRequestHandler.format\_response

```python
@staticmethod
def format_response(resp: typing.Any) -> typing.Tuple[str, str]
```

Formats a response as JSON.

**Arguments**:

- `resp` _Any_ - The response data.
  

**Returns**:

  Tuple[str, str]: The JSON response and its content type.

<a id="usrv.route.uHTTPRequestHandler.do_"></a>

### uHTTPRequestHandler.do\_

```python
def do_(method: str = "GET") -> int
```

Processes an HTTP request and calls the appropriate endpoint.

**Arguments**:

- `method` _str_ - The HTTP method (e.g., "GET", "POST").
  Defaults to "GET".
  

**Returns**:

- `int` - Status code of the response.

<a id="usrv.route.bind"></a>

## bind

```python
def bind(path: str,
         methods: list = ["GET"],
         target: BaseHTTPRequestHandler = uHTTPRequestHandler) -> Callable
```

Binds a function to a specific URL path and HTTP methods.

**Arguments**:

- `path` _str_ - The URL path to bind.
- `methods` _list_ - List of HTTP methods (e.g., ["GET", "POST"]).
- `target` _BaseHTTPRequestHandler_ - The request handler class.
  

**Returns**:

- `Callable` - A decorator that binds the function.

<a id="usrv.route.callback"></a>

## callback

```python
def callback(url: str, headers: dict, data: str, function: Callable,
             markups: OrderedDict, regexp: re.Pattern,
             arg_spec: inspect.FullArgSpec) -> typing.Any
```

Handles the execution of the bound function with appropriate arguments.
the last 4 parameters are defined by the bind function and stored in the
lambda callback.

**Arguments**:

- `url` _str_ - The full URL of the request.
- `headers` _dict_ - The HTTP headers from the request.
- `data` _str_ - The body of the request.
- `function` _Callable_ - The function to execute.
- `markups` _OrderedDict_ - Mappings of path variables to their types.
- `regexp` _re.Pattern_ - Compiled regex for path matching.
- `arg_spec` _FixArgSpec_ - Argument specification of the function.
  

**Returns**:

- `Any` - The result of the function execution.

<a id="usrv.route.run"></a>

## run

```python
def run(host: str = "127.0.0.1", port: int = 5000, loglevel: int = 20) -> None
```

Starts the HTTP server.

**Arguments**:

- `host` _str_ - The IP address to bind to. Defaults to "127.0.0.1".
- `port` _int_ - The port to bind to. Defaults to 5000.
- `loglevel` _int_ - Logging level. Defaults to 20.

