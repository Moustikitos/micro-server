[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/Moustikitos/micro-server/master/LICENSE)

Micro IO package (`usrv`) is a pure python JSON server implementation.

### Support this project
 
 [![Liberapay receiving](https://img.shields.io/liberapay/goal/Toons?logo=liberapay)](https://liberapay.com/Toons/donate)
 
 [Buy &#1126;](https://bittrex.com/Account/Register?referralCode=NW5-DQO-QMT) and:
 
   * [X] Send &#1126; to `AUahWfkfr5J4tYakugRbfow7RWVTK35GPW`
   * [X] Vote `arky` on [Ark blockchain](https://explorer.ark.io) and [earn &#1126; weekly](http://dpos.arky-delegate.info/arky)

# Install

```
$ pip install git+https://github.com/Moustikitos/micro-server#egg=usrv
```

# `usrv.srv`

Run a very low footprint python server or [PEP#3333 WSGI server](https://www.python.org/dev/peps/pep-3333). Bind python code to any HTTP requests easily using decorator syntax.

`srv` module can be used in standalone mode outside of `usrv` package.

## Fast and simple

Let's create a server with `/test` endpoint in a python module named `test.py`:

```python
from usrv import srv

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
INFO:usrv.srv:listening on 127.0.0.1:5000
CTRL+C to stop...
```

Now going to `127.0.0.1:5000/test` with any browser gives:
```
{"status": 200, "result": [null, null]}
```

## Extracting values from url query

`[null, null]` above are the returned values `a` and `b` from `do_test` function. They can be extracted from query string. Let's type `127.0.0.1:5000/test?b=12&a=Paris` in the address bar:

```
{"status": 200, "result": ["Paris", "12"]}
```

Returned value from query are `str` only. Unexpected values are ignored but there is a [convenient way to catch them](#catching-unexpected-values).

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

Values from url can be overrided by thoses from query... `http://127.0.0.1:5000/5/test?a=2&b=6`:

```
{"status": 200, "result": ["2", "6"]}
```

## Catching unexpected values...

Using varargs or/and keywordargs is a convenient way to catch unexpected values from url query and HTTP context. HTTP Context is defined by a method, a full url, headers and data as python dictionary.

When HTTP context is catched by `*args`, unexpected values from query string are appended next.

Url used for this chapter `127.0.0.1:5000/test?b=12&a=Paris&unexpected=there`.

### Varargs (`*args`)

```python
@srv.bind("/test")
def do_test(a, b, *args):
    # write some code and return something
    # args is a tuple
    return a, b, args
```

```
{"status": 200, "result": ["Paris", "12", ["GET", "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", {"host": "127.0.0.1:5000", "connection": "keep-alive", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, {}, "there"]]}
```

### Keywordargs (`**kwargs`)

```python
@srv.bind("/test")
def do_test(a, b, **kwargs):
    # write some code and return something
    # kwargs is a dict
    return a, b, kwargs
```

```
{"status": 200, "result": ["Paris", "12", {"unexpected": "there", "url": "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", "headers": {"host": "127.0.0.1:5000", "connection": "keep-alive", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, "data": {}, "method": "GET"}]}
```

### Both (`*args`, `**kwargs`)

```python
@srv.bind("/test")
def do_test(a, b, *args, **kwargs):
    # write some code and return something
    return a, b, args, kwargs
```

```
{"status": 200, "result": ["Paris", "12", ["there"], {"url": "http://127.0.0.1:5000/test?b=12&a=Paris&unexpected=there", "headers": {"host": "127.0.0.1:5000", "connection": "keep-alive", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br", "accept-language": "fr,en-US;q=0.9,en;q=0.8"}, "data": {}, "method": "GET"}]}
```

### Command line

Server can be launched from command line using python module names for bindings. Modules containing binded code have to be found by python. This is not recomended for production.

```
Usage: srv.py [options] BINDINGS...

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -s, --ssl             activate ssl socket wraping
  -l LOGLEVEL, --log-level=LOGLEVEL
                        set log level from 1 to 50 [default: 20]
  -i HOST, --ip=HOST    ip to run from             [default: 127.0.0.1]
  -p PORT, --port=PORT  port to use                [default: 5000]
```

### Run behind a WSGI 

`srv.MicroJsonApp()` can be run behind a python WSGI like [`gunicorn`](https://gunicorn.org/):

```bash
$ gunicorn 'srv:MicroJsonApp()' --bind=0.0.0.0:5000
```

`gunicorn` needs an instance of `srv.MicroJsonApp`, it may be configured in a python module and have to be pointed by command line.

Let's consider `wsgi.py` module bellow:

```python
from usrv import srv
import bindings

# here is the instance gunicorn looks for
app = srv.MicroJsonApp(host="127.0.0.1", port=5000, loglevel=10)
```

```bash
$ gunicorn 'wsgi:app' --bind=0.0.0.0:5000
```

## `usrv.req`

Provides a pythonic way to fetch http calls.

### Bodyless HTTP calls

Http calls `GET`, `DELETE`, `HEAD`, `OPTIONS` and `TRACE` are bodyless ie no data can be sent. All keyword arguments will be converted into an url query string.

```python
from usrv import req

# first connect to a peer
req.connect("https://dexplorer.ark.io:8443")
# https://dexplorer.ark.io:8443/api/delegates
resp = req.GET.api.delegates()
# https://dexplorer.ark.io:8443/api/delegates?orderBy=username:asc
resp = req.GET.api.delegates(orderBy="username:asc")
```

### Other HTTP calls

Http calls `CONNECT`, `POST`, `PATCH`, `PUT` and `DELETE` allow data to be sent. Data can be sent as json-string, url-encoded-string or multipart/form-data using specific peer and headers.

If no specific keyword is used, keyword arguments are sent as json string in the request body.

### Specific keywords

#### `_jsonify`

Keyword used so body content is sent as json.

#### `_urlencode`

Keyword used so body content is sent as urlencoded string.

#### `_multipart`

Keyword used so body content is sent as multipart/form-data format specified in [RFC#7578](https://datatracker.ietf.org/doc/html/rfc7578). Value provided to `_multipart` keyword can be either a Python `dict` object or a `usrv.req.FormDict` class. `dict` are blindly encoded by `req.FormData.blind_encode` static method.

```python
>>> data, header = req.FormData.blind_encode(key="value") 
>>> print(data)
--b8f8d72ec06269a8f4dc94052b9bd72f
Content-Disposition: form-data; name="key"
Content-Type: text/plain; charset=UTF-8

value
--b8f8d72ec06269a8f4dc94052b9bd72f--

>>> print(header)
multipart/form-data; boundary=b8f8d72ec06269a8f4dc94052b9bd72f
```

#### `peer`

Keyword used to define a custom peer in the request.

```python
# https://dexplorer.ark.io:8443/api/delegates?orderBy=username:asc
resp = req.GET.api.delegates(orderBy="username:asc", peer="https://dexplorer.ark.io:8443")
```

#### `headers`

Keyword used to define custom headers in the request.

# Plugins

## [IpInfo](https://www.ipinfo.io)

```python
>>> from usrv import ipinfo
>>> ipinfo.link("ba4[...]d1a")  # Ipinfo API token
>>> ipinfo.info("8.8.8.8")   
{'ip': '8.8.8.8', 'hostname': 'dns.google', 'anycast': True, 'city': 'Mountain View', 'region': 'California', 'country': 'US', 'loc': '37.4056,-122.0775', 'org': 'AS15169 Google LLC', 'postal': '94043', 'timezone': 'America/Los_Angeles', 'status': 200}
```

Check server location : [`Mountain View`](https://www.latlong.net/c/?lat=37.4056&long=-122.0775)

## [Pinata](https://www.pinata.cloud/)

```python
>>> from usrv import pinata
>>> pinata.link("eyJhb[...]rI7QY")  # JWT token
>>> pinata.pinFile(r"C:\Users\Toons\Pictures\arky.png", name="arky delegate logo")
{'IpfsHash': 'QmT7V4pYNSopJHxKvYDxYrmrtCizv9PR5FJ5FkryVfiakP', 'PinSize': 25293, 'Timestamp': '2021-11-20T21:13:36.853Z', 'status': 200}
```

Check pinned file here : `ipfs://QmT7V4pYNSopJHxKvYDxYrmrtCizv9PR5FJ5FkryVfiakP`
