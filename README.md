[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/Moustikitos/micro-io/master/LICENSE)

Micro IO package (`uio`) is a pure python light JSON server implementation running on native python libraries.

# `uio.srv`

Run a very low footprint python server or [PEP#3333 WSGI server](https://www.python.org/dev/peps/pep-3333). Bind python code to any HTTP requests easily using decorator syntax.

## Quickstart

Let's create a server with a simple `/test` endpoint in a python module named `test.py`:

```python
from uio import srv

@srv.bind("/test")
def do_test(a, b):
    # write some code and return something
    return a, b

def launchApp():
    app = srv.MicroJsonApp(host="127.0.0.1", port=5000, loglevel=10)
    app.run(ssl=False)
```

Server can be run from python interpreter:

```python
>>> import test
>>> test.launchApp()
INFO:uio.srv:listening on 127.0.0.1:5000
CTRL+C to stop...
```

## Extracting values from url query

Now going to `127.0.0.1:5000/test` with any browser gives:
```
{"status": 200, "result": [null, null]}
```

`[null, null]` are the returned values `a` and `b` from `do_test` function. They can be extracted from query string. Let's type `127.0.0.1:5000/test?b=12&a=Paris` in the address bar:

```
{"status": 200, "result": ["Paris", "12"]}
```

Returned value from query strig are `str` only. Unexpected values in the query string are ignored but there is a [convenient way to catch them](#catching-unexpected-values).

## Extracting values from url path

Values can also be extracted from url path with or without a typing precision.

```python
@srv.bind("/<int:b>/<a>")
def do_test(a, b):
    # write some code and return something
    return a, b
```

This binding creates multiple endpoint possibilities. Let's try `127.0.0.1:5000/5/test`:

```
{"status": 200, "result": ["test", 5]}
```

Value extracted from url can be overrided by thoses from query... `http://127.0.0.1:5000/5/test?a=2&b=6`:

```
{"status": 200, "result": ["2", "6"]}
```

## Catching unexpected values...

```python
@srv.bind("/test")
def do_test(a, b, *args):
    # write some code and return something
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
    # write some code and return something
    # kwargs is a dict
    return a, b, kwargs
```

Result from `127.0.0.1:5000/test?b=12&a=Paris&unexpected=there`:

```
{"status": 200, "result": ["Paris", "12", {"unexpected": "there", "url": "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", "headers": {"host": "127.0.0.1:5000", "connection": "keep-alive", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, "data": {}, "method": "GET"}]}
```

## `uio.req`

## `uio.zjsn`

## Plugins

### `bittrex`

### `ipinfo`

### `notify`
