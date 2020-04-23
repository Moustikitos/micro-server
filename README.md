[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/Moustikitos/micro-io/master/LICENSE)

# `uio`

Micro IO package (`uio`) is a pure python light JSON server implementation running on native python libraries.

## `uio.srv`

Run a very low footprint python server or [PEP#3333 WSGI server](https://www.python.org/dev/peps/pep-3333). Bind python code to any HTTP requests easily using decorator syntax.

### Quickstart

Let's create a server with a simple `/test` endpoint in a python module named `test.py`:

```python
from uio import srv

@srv.bind("/test")
def do_test(a, b):
    # write some coding and return something
    return a, b

def launchApp():
    app = srv.MicroJsonApp(host="127.0.0.1", port=5000, loglevel=10)
    app.run(ssl=False)
```

And then run the server using python interpreter:

```python
>>> import test
>>> test.launchApp()
INFO:uio.srv:listening on 127.0.0.1:5000
CTRL+C to stop...
```

Now going to `127.0.0.1:5000/test` with any browser gives:
```
{"status": 200, "result": [null, null]}
```

`[null, null]` are the returned values `a` and `b` from `do_test` function. Parameter values are extracted from query string. Let's type `127.0.0.1:5000/test?b=12&a=Paris` in the address bar:

```
{"status": 200, "result": ["Paris", "12"]}
```

Unexpected values in the query string are ignored. But there is a convenient way to catch them rewriting the function with varargs:

```python
@srv.bind("/test")
def do_test(a, b, *args):
    # write some coding and return something
    # args is a tuple
    return a, b, args
```

Result from `127.0.0.1:5000/test?b=12&a=Paris&unexpected=there`:

```
{"status": 200, "result": ["Paris", "12", ["GET", "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", {"host": "127.0.0.1:5000", "connection": "keep-alive", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, {}, "there"]]}
```

All HTTP context (method, url, headers and data) is catched by `*args`. Unexpected values from query string are appended next. This is quite nice, but there is a more convenient way to catch HTTP context and unexpected values: kwargs

```python
@srv.bind("/test")
def do_test(a, b, **kwargs):
    # write some coding and return something
    # kwargs is a dict
    return a, b, kwargs
```

Result from `127.0.0.1:5000/test?b=12&a=Paris&unexpected=there`:

```
{"status": 200, "result": ["Paris", "12", {"unexpected": "there", "url": "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", "headers": {"host": "127.0.0.1:5000", "connection": "keep-alive", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, "data": {}, "method": "GET"}]}
```

Use of kwargs is highly recomended for readability.

## `uio.req`

## `uio.zjsn`

## Plugins

### `bittrex`

### `ipinfo`

### `notify`
