# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module can be run indepenently from the `uio` package. It contains all
the utilities to launch a json server (ie, you get and send json) from python
lib or python WGSI (highly recommended in production mode).

  * to run server from python:
```bash
$ python srv.py -h
Usage: srv.py [options] BINDINGS...

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -s, --ssl             activate ssl socket wraping
  -l LOGLEVEL, --log-level=LOGLEVEL
                        set log level
  -i HOST, --ip=HOST    ip to run from
  -p PORT, --port=PORT  port to use
```

BINDINGS is a list of python modules containing python binded functions.
>>> from uio import srv
>>> @srv.bind("/endpoint/path")
>>> def do_something(a, b, *args, **kwargs):
>>>    # do some coding...
>>>    return (a, b)+args, kwargs

  * to run server behind a WSGI, point to a `MicroJsonApp` instance:
```bash
$ gunicorn 'srv:MicroJsonApp()' --bind=0.0.0.0:5000
```
"""

import os
import sys
import ssl
import json
import inspect
import logging
import traceback
import importlib

from collections import OrderedDict
from optparse import OptionParser

if sys.version_info[0] >= 3:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse as urlparse
    quote = urlparse.quote

    def getHeader(http_msg, key, alt=False):
        return http_msg.get(key, alt)

    def inspectBinded(function):
        params = inspect.signature(function).parameters.values()
        args = [p.name for p in params if p.kind == p.POSITIONAL_OR_KEYWORD]
        uses_vargs = any([p for p in params if p.kind == p.VAR_POSITIONAL])
        uses_kwargs = any([p for p in params if p.kind == p.VAR_KEYWORD])
        return args, uses_vargs, uses_kwargs

else:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from urllib import quote
    import urlparse

    def getHeader(http_msg, key, alt=False):
        http_msg.getheader(key, alt)

    def inspectBinded(function):
        ins = inspect.getargspec(function)
        return (
            ins.args,
            ins.varargs is not None,
            ins.keywords is not None
        )

    json.JSONDecodeError = ValueError

LOGGER = logging.getLogger("uio.srv")
logging.basicConfig()


class Capsule:
    """
    Function container.
    """

    def __init__(self, func, **params):
        self.func = func
        self.__dict__.update(params)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


def bind(path, methods=["GET"]):
    """
    Link a python function to an http request. This definition is meant to be
    used as a decorator. It allows server context execution aquirement via
    varargs or keyword args of the decorated function. Positional arguments
    are extracted from url query string, value is either `None` (no match in
    query string) or `str` type.

    to register an endpoint :
    >>> @bind("/endpoint/path")
    >>> def do_something(a, b):
    >>>    # do some coding
    >>>    return a, b

    or
    >>> def do_something_else(a, b, *args):
    >>>    # do some coding
    >>>    return (a, b) + args
    >>> bind("/endpoint/path", methods=["POST"])(do_something_else)

    Args:
        path (:class:`str`): endpoint path
        methods (:class:`list`): list of http request to bind with
    Returns:
        :mod:`decorator`: decorated function
    """

    def decorator(function):
        args, uses_vargs, uses_kwargs = inspectBinded(function)

        # create the wrapper called by _call
        def wrapper(method, url, headers, data):
            # get parameters from url query string
            parse_qsl = urlparse.parse_qsl(urlparse.urlparse(url).query)
            not_positional = dict(
                (k, v) for k, v in parse_qsl if k not in args
            )
            positional = tuple(
                OrderedDict(
                    [(k, None) for k in args],
                    **OrderedDict((k, v) for k, v in parse_qsl if k in args)
                ).values()
            )
            kwargs = {}
            if uses_kwargs:
                kwargs.update(
                    not_positional,
                    **{
                        "url": url, "headers": headers,
                        "data": data, "method": method
                    }
                )
            elif uses_vargs:
                positional += \
                    (method, url, headers, data) + \
                    tuple(not_positional.values())
            return function(*positional, **kwargs)
        # register wrapper in a container used to keep informations computed
        # during registration
        container = Capsule(
            wrapper, wrapped=function.__name__,
            path=path, methods=methods,
            inspect={
                "args": args, "uses_vargs": uses_vargs,
                "uses_kwargs": uses_kwargs
            }
        )
        for method in methods:
            MicroJsonApp.ENDPOINTS[method] = dict(
                MicroJsonApp.ENDPOINTS.get(method, {}), **{path: container}
            )
            LOGGER.debug(
                ">>> %s bound to 'HTTP %s %s' request",
                function.__name__, method, path
            )
        return wrapper
    return decorator


def _rebuild_url(env):
    """
    Rebuild full url from WSGI environement according to PEP #3333.
    https://www.python.org/dev/peps/pep-3333
    """
    url = env['wsgi.url_scheme'] + '://'

    if env.get('HTTP_HOST'):
        url += env['HTTP_HOST']
    else:
        url += env['SERVER_NAME']

        if env['wsgi.url_scheme'] == 'https':
            if env['SERVER_PORT'] != '443':
                url += ':' + env['SERVER_PORT']
        else:
            if env['SERVER_PORT'] != '80':
                url += ':' + env['SERVER_PORT']

    url += quote(env.get('SCRIPT_NAME', ''))
    url += quote(env.get('PATH_INFO', ''))

    if env.get('QUERY_STRING'):
        url += '?' + env['QUERY_STRING']

    return url


def _call(func, method, url, header, data):
    if func is None:
        LOGGER.error("no endpoind found behind %s", url)
        return {"status": 400, "result": "not found"}
    else:
        try:
            result = func(method, url, header, json.loads(data))
        except json.JSONDecodeError as error:
            LOGGER.error("%r\n%s", error, traceback.format_exc())
            status = 406
            result = "data is not a valid json string"
        except Exception as error:
            LOGGER.error("%r\n%s", error, traceback.format_exc())
            status = 500
            result = "%s raise an error: %r" % (func, error)
        else:
            status = 200
    return {"status": status, "result": result}


class MicroJsonApp:

    ENDPOINTS = {}

    def __init__(self, host="127.0.0.1", port=5000, loglevel=20):
        LOGGER.setLevel(loglevel)
        self.host = host
        self.port = port

    def __call__(self, environ, start_response):
        """
        Web Server Gateway Interface for deployment.
        https://www.python.org/dev/peps/pep-3333
        """
        method = environ["REQUEST_METHOD"]

        func = MicroJsonApp.ENDPOINTS.get(method, {}).get(
            environ.get("PATH_INFO", "/"), None
        )

        if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
            http_input = "{}"
        else:
            http_input = environ["wsgi.input"].read()

        data = _call(
            func, method, _rebuild_url(environ),
            dict(
                [k.replace("HTTP_", "").replace("_", "-").lower(), v]
                for k, v in environ.items() if k.startswith("HTTP_")
            ),
            http_input.decode("latin-1") if isinstance(http_input, bytes)
            else http_input
        )

        statuscode = "%d" % data["status"]
        data = json.dumps(data)

        write = start_response(
            statuscode.decode("latin-1") if isinstance(statuscode, bytes)
            else statuscode,
            (["Content-type", "application/json"],)
        )
        write(data.encode("latin-1") if not isinstance(data, bytes) else data)
        return b""

    def wrap(self):
        if not hasattr(self, "httpd"):
            LOGGER.error("ssl wrap done only if server runs from python lib")
            return
        path = os.path.dirname(os.path.abspath(__file__))
        try:
            if not os.path.exists("%s/cert.pem" % path):
                os.system(
                    "openssl req -x509 -newkey rsa:2048 "
                    "-keyout %(path)s/key.pem -out %(path)s/cert.pem -days 365"
                    % {"path": path}
                )
        except Exception as error:
            LOGGER.error("%r\n%s", error, traceback.format_exc())
        else:
            if os.path.exists("%s/cert.pem" % path):
                self.httpd.socket = ssl.wrap_socket(
                    self.httpd.socket,
                    keyfile="%s/key.pem" % path,
                    certfile="%s/cert.pem" % path,
                    server_side=True
                )

    def run(self, ssl=False):
        """
        For testing purpose only.
        """
        self.httpd = HTTPServer((self.host, self.port), MicroJsonHandler)
        if ssl:
            self.wrap()
            LOGGER.info("ssl socket wrapping done")
        try:
            LOGGER.info(
                "listening on %s:%s\nCTRL+C to stop...",
                self.host, self.port
            )
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            LOGGER.info("server stopped")


class MicroJsonHandler(BaseHTTPRequestHandler):

    def __getattr__(self, attr):
        if attr.startswith("do_"):
            return lambda o=self: \
                MicroJsonHandler.do_(o, attr.replace("do_", ""))
        return BaseHTTPRequestHandler.__getattribute__(self, attr)

    @staticmethod
    def do_(self, method="GET"):
        func = MicroJsonApp.ENDPOINTS.get(method, {}).get(self.path.split("?")[0], None)
        address, port = self.server.server_address

        if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
            http_input = "{}"
        else:
            length = getHeader(self.headers, 'content-length')
            http_input = self.rfile.read(
                int(length) if length is not None else 0
            )

        url = \
            "https://%s:%s%s" if isinstance(self.server.socket, ssl.SSLSocket)\
            else "http://%s:%s%s"

        data = _call(
            func, method, url % (address, port, self.path),
            dict([k.lower(), v] for k, v in dict(self.headers).items()),
            http_input.decode("latin-1") if isinstance(http_input, bytes)
            else http_input
        )

        return self.close_request(data["status"], data)

    def close_request(self, value, resp):
        data = json.dumps(resp)
        self.send_response(value)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(
            data if isinstance(data, bytes) else data.encode("latin-1")
        )


def main():
    parser = OptionParser(
        usage="usage: %prog [options] BINDINGS...",
        version="%prog 1.0"
    )
    parser.add_option(
        "-s", "--ssl", action="store_true", dest="ssl", default=False,
        help="activate ssl socket wraping"
    )
    parser.add_option(
        "-l", "--log-level", action="store", dest="loglevel", default=50,
        type="int", help="set log level"
    )
    parser.add_option(
        "-i", "--ip", action="store", dest="host", default="127.0.0.1",
        help="ip to run from"
    )
    parser.add_option(
        "-p", "--port", action="store", dest="port", default=5000,
        type="int", help="port to use"
    )
    (options, args) = parser.parse_args()

    app = MicroJsonApp(options.host, options.port, loglevel=options.loglevel)

    # if no bindings, register few endpoints for testing purpose
    if len(args) == 0 and __name__ == "__main__":
        # url, headers, data and method loosed
        @bind("/")
        def test0(a, b):
            return a, b
        # get url, headers, data and method in args
        @bind("/vargs")
        def test1(a, b, *args):
            return (a, b) + args
        # get url, headers, data and method in kwargs
        @bind("/kwargs")
        def test2(a, b, **kwargs):
            return a, b, kwargs
        # get url, headers, data and method in kwargs
        @bind("/vargs_kwargs")
        def test3(a, b, *args, **kwargs):
            return (a, b) + args, kwargs
    else:
        for name in args:
            try:
                importlib.import_module(name)
            except ImportError as error:
                LOGGER.error("%r\n%s", error, traceback.format_exc())

    # namespace fix :
    # __main__.MicroJsonApp.ENDPOINTS has to be updated
    uio_srv = sys.modules.get("uio.srv", None)
    if uio_srv is not None:
        MicroJsonApp.ENDPOINTS.update(
            uio_srv.MicroJsonApp.ENDPOINTS
        )

    app.run(ssl=options.ssl)


if __name__ == "__main__":
    main()
