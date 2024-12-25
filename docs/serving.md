<a id="usrv.app"></a>

# app

This module contains all the utilities to launch a WSGI micro server (highly
recommended in production mode).

<a id="usrv.app.uApp"></a>

## uApp Objects

```python
class uApp()
```

Represents a lightweight application server that can handle HTTP requests,
optionally wrap its socket with SSL, and run in a testing mode.

**Attributes**:

- `handler` _BaseHTTPRequestHandler_ - HTTP request handler.
- `host` _str_ - The hostname for the server.
- `port` _int_ - The port number for the server.

<a id="usrv.app.uApp.__init__"></a>

### uApp.\_\_init\_\_

```python
def __init__(host: str = "127.0.0.1",
             port: int = 5000,
             loglevel: int = 20,
             handler: BaseHTTPRequestHandler = route.uHTTPRequestHandler)
```

Initializes the uApp instance with a specified host, port, logging
level, and request handler.

**Arguments**:

- `host` _str_ - Hostname for the server. Defaults to "127.0.0.1".
- `port` _int_ - Port number for the server. Defaults to 5000.
- `loglevel` _int_ - Logging level. Defaults to 20 (INFO).
- `handler` _BaseHTTPRequestHandler_ - Request handler.
  Defaults to `route.uHTTPRequestHandler`.

<a id="usrv.app.uApp.__call__"></a>

### uApp.\_\_call\_\_

```python
def __call__(environ: dict, start_response: Callable) -> bytes
```

Enables the application to be callable as a WSGI application.

**Arguments**:

- `environ` _dict_ - The WSGI environment dictionary.
- `start_response` _callable_ - A callable to start the HTTP response.
  

**Returns**:

- `Callable` - The response iterable.

<a id="usrv.app.uApp.wrap"></a>

### uApp.wrap

```python
def wrap() -> bool
```

Wraps the HTTP server's socket with SSL if a certificate and key are
available.

**Returns**:

- `bool` - True if the socket is successfully wrapped with SSL, False
  otherwise.

<a id="usrv.app.uApp.run"></a>

### uApp.run

```python
def run(ssl: bool = False)
```

Starts the HTTP server, optionally wrapping the socket with SSL.
This method is designed for testing purposes only.

**Arguments**:

- `ssl` _bool_ - If True, wraps the server's socket with SSL. Defaults
  to False.

