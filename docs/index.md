# `usrv`: the lightest python server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/Moustikitos/micro-server/master/LICENSE)

Package (`usrv`) is a pure python micro server implementation.

## Install

```bash
$ pip install git+https://github.com/Moustikitos/micro-server#egg=usrv
```

## `usrv.route`

Bind python code to any HTTP requests easily using decorator syntax.
`route` module can be used in standalone mode outside of `usrv` package.

## `usrv.app`

Run a low footprint python server or [PEP#3333 WSGI server](https://www.python.org/dev/peps/pep-3333).

```python
import waitress  # wsgi server for windows
from usrv import app, route

@route.bind("/index")
def index(**kw):
    return 200, "Index page", kw

waitress.serve(app.uApp(), threads=2)
```

## Fast and simple

Let's create a server with `/test` endpoint in a python module named `test.py`:

```python
from usrv import route, app

@route.bind("/test")
def do_test(a, b):
    # write some code and return something
    return 200, a, b

def launchApp():
    route.run(host="127.0.0.1", port=5000, loglevel=20)
```

**Bound functions have to return a tuple with a valid HTTP status code as first item**.
Server can be run from python interpreter:

```python
>>> import test
>>> test.launchApp()
INFO:usrv.srv:listening on 127.0.0.1:5000
CTRL+C to stop...
```

Now going to `http://127.0.0.1:5000/test` with any browser gives:

```json
[null, null]
```

## Extracting values from url query

`[null, null]` above are the returned values `a` and `b` from `do_test` function. Values can be extracted from query string. Let's type `http://127.0.0.1:5000/test?b=12&a=Paris` in the address bar:

```json
["Paris", "12"]
```

Returned value from query are `str` only. Unexpected values are ignored but there is a [convenient way to catch them](#catching-unexpected-values).

## Extracting values from url path

Values can also be extracted from url path with or without a typing precision.

```python
@srv.bind("/<int:b>/<a>")
def do_test(a, b):
    # write some code and return something
    return 200, a, b
```

This binding creates multiple endpoint possibilities. Let's try `http://127.0.0.1:5000/5/test`:

```json
["test", 5]
```

Values from url can be overrided by thoses from query... `http://127.0.0.1:5000/5/test?a=2&b=6`:

```json
["2", "6"]
```

> It can only be overrided with `str` type values.

## Catching unexpected values

Using varargs or/and keywordargs is a convenient way to catch unexpected values from url query and HTTP context. HTTP Context is defined an headers and data (HTTP requests with body).

When HTTP context is catched by `*args`, unexpected values from query string are appended next.

Url used for this chapter `http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there`.

### Variable args (`*args`)

```python
@srv.bind("/test")
def do_test(a, b, *args):
    # write some code and return something
    # args is a tuple
    return 200, a, b, args
```

> With `*args` method, HTTP headers and data will be postionned at the end of `json` response

```json
[
  "Paris",
  "12",
  "there",
  "GET",
  {
    "host": "127.0.0.1:5000",
    "connection": "keep-alive",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-gpc": "1",
    "accept-language": "fr-FR,fr",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd"
  },
  null
]
```

### Keyword args (`**kwargs`)

```python
@srv.bind("/test")
def do_test(a, b, **kwargs):
    # write some code and return something
    # kwargs is a dict
    return 200, a, b, kwargs
```

> using `**kwargs` is the recommended way to retrieve unexpected values by names. Unexpected mapping is positionned at the end of `json` response.

```json
[
  "Paris",
  "12",
  {
    "unexpected": "there",
    "method": "GET",
    "headers": {
      "host": "127.0.0.1:5000",
      "connection": "keep-alive",
      "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": "\"Windows\"",
      "upgrade-insecure-requests": "1",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      "sec-gpc": "1",
      "accept-language": "fr-FR,fr",
      "sec-fetch-site": "none",
      "sec-fetch-mode": "navigate",
      "sec-fetch-user": "?1",
      "sec-fetch-dest": "document",
      "accept-encoding": "gzip, deflate, br, zstd"
    },
    "data": null,
  }
]
```

## Command line

WSGI server can be launched from command line.

```bash
$ python wsgi_srv.py -h
Usage: wsgi_srv.py [options] BINDINGS...

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

`BINDINGS` is a space-separated-list of python module names (ie no `*.py` extention) containing boud python functions. Modules containing bound functions have to be in one of `sys.path` folder. Specific folder can be added using `wsgi_srv.path` file.

## Support this project

[![Liberapay receiving](https://img.shields.io/liberapay/goal/Toons?logo=liberapay)](https://liberapay.com/Toons/donate)
[![Paypal me](https://img.shields.io/badge/PayPal-toons-00457C?logo=paypal&logoColor=white)](https://paypal.me/toons)
<!-- [![Bitcoin](https://img.shields.io/badge/Donate-bc1q6aqr0hfq6shwlaux8a7ydvncw53lk2zynp277x-ff9900?logo=bitcoin)](https://raw.githubusercontent.com/Moustikitos/python-mainsail/master/docs/img/bc1q6aqr0hfq6shwlaux8a7ydvncw53lk2zynp277x.png) -->
