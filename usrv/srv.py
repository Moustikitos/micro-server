# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module can be run indepenently from the `usrv` package. It contains all
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
                        set log level from 1 to 50 [default: 20]
  -i HOST, --ip=HOST    ip to run from             [default: 127.0.0.1]
  -p PORT, --port=PORT  port to use                [default: 5000]
```

BINDINGS is a list of python modules containing python binded functions.

  * to run server behind a WSGI, point to a `MicroJsonApp` instance:
```bash
$ gunicorn 'srv:MicroJsonApp()' --bind=0.0.0.0:5000
```
"""

import os
import re
import ssl
import json
import inspect
import logging
import traceback
import importlib

from usrv import uroot
from collections import OrderedDict, namedtuple
from optparse import OptionParser

from http.server import HTTPServer
import urllib.parse as urlparse

LOGGER = logging.getLogger("usrv.srv")
logging.basicConfig()
FixArgSpec = namedtuple(
    "FixArgSpec", (
        'args', 'varargs', 'varkw', 'defaults', 'kwonlyargs',
        'kwonlydefaults', 'annotations', "keywords"
    )
)


def _get_arg_spec(function):
    insp = inspect.getfullargspec(function)
    _insp = FixArgSpec(**dict(insp._asdict(), keywords=insp.varkw))
    return _insp


class MatchDict(dict):

    # this patern matches <> enclosed characters (markup)
    PATTERN = re.compile("<([^><]*)>")

    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self._matchers = {}

    def __setitem__(self, item, value):
        # --> `srv.bind` decorator set a Capsule instance to url path (item)
        if isinstance(item, str) and isinstance(value, Capsule):
            found = MatchDict.PATTERN.findall(item)
            # if markup pattern found in url
            if len(found):
                # create a regexp replacing all markup by '([^/]*)'
                # '/person/<name>/<int:age>' --> '/person/([^/])*/([^/]*)'
                regexp = re.compile(
                    "^%s$" % MatchDict.PATTERN.sub("([^/]*)", item)
                )
                # pattern could be 'name' or 'type:name'
                # 'name'.split(":") == ["name"]
                # 'type:name'.split(":") == ["type", "name"]
                # tn[-1] == "name"
                # vars_ is a dict([('name', type)...])
                vars_ = OrderedDict(
                    [tn[-1], __builtins__.get(tn[0], "str")] for tn in [
                        elem.split(":") for elem in found
                    ]
                )
                # add 'urlmatch' attribute to Capsule instance
                setattr(value, "urlmatch", (vars_, regexp))
                self._matchers[item] = (vars_, regexp)
        return dict.__setitem__(self, item, value)

    def get(self, item, default=None):
        # try to get item as for a normal dict
        value = dict.get(
            self, item, self._matchers.get(
                item, default
            )
        )
        if value is not None:
            return value
        # if no value found then it could be a string that matches any of
        # regexp stored in _matchers
        elif isinstance(item, str):
            for path, (pattern, regexp) in self._matchers.items():
                if regexp.match(item) is not None:
                    return dict.get(self, path, default)
        return default


class Capsule:
    """
    Function container.
    """

    def __init__(self, func, **params):
        self.func = func
        self.__dict__.update(params)

    def __call__(self, *args, **kwargs):
        # if `srv.bind` set an urlmatch tuple, set it to decorated function
        setattr(
            self.func, "urlmatch", getattr(
                self, "urlmatch", [None, None]
            )
        )
        return self.func(*args, **kwargs)


class uApp:

    def __init__(
        self, host="127.0.0.1", port=5000, loglevel=20,
        handler=uroot.uRawHandler
    ):
        LOGGER.setLevel(loglevel)
        self.handler = handler
        self.host = host
        self.port = port

    def __call__(self, environ, start_response):
        return uroot.wsgi_call(self.handler, environ, start_response)

    def wrap(self):
        if not hasattr(self, "httpd"):
            LOGGER.error("ssl wrap done only if server runs from python lib")
            return False
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
            return False
        else:
            if os.path.exists("%s/cert.pem" % path):
                self.httpd.socket = ssl.wrap_socket(
                    self.httpd.socket,
                    keyfile="%s/key.pem" % path,
                    certfile="%s/cert.pem" % path,
                    server_side=True
                )
                return True
        return False

    def run(self, ssl=False):
        """
        For testing purpose only.
        """
        self.httpd = HTTPServer((self.host, self.port), self.handler)
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


class uJsonHandler(uroot.uRawHandler):

    @staticmethod
    def format_response(resp):
        return json.dumps(resp or {}), "application/json"


class uJsonApp(uApp):

    def __init__(self, host="127.0.0.1", port=5000, loglevel=20):
        LOGGER.setLevel(loglevel)
        self.handler = uJsonHandler
        self.host = host
        self.port = port


def bind(path, methods=["GET"], app=uroot.uRawHandler):
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
        path (:class:`str`):
            endpoint path
        methods (:class:`list`):
            list of http request to bind with [default: ['GET']]
    Returns:
        :func:`decorator`: decorated function
    """
    if path != "/":
        if not path.startswith("/"):
            path = "/" + path
        if path.endswith("/"):
            path = path[:-1]

    def decorator(function):
        # inspect function
        insp = _get_arg_spec(function)

        def wrapper(method, url, headers, data):
            # get path and query from url
            parse = urlparse.urlparse(url)
            parse_qsl = urlparse.parse_qsl(parse.query)

            # gather variables from url path
            _urlmatch = {}
            vars_, regexp = getattr(wrapper, "urlmatch", [None, None])
            if vars_ is not regexp:  # ie vars != None and regexp != None
                try:
                    for (name, typ_), value in zip(
                        vars_.items(), regexp.match(parse.path).groups()
                    ):
                        _urlmatch[name] = typ_(value)
                except Exception as error:
                    LOGGER.error("%r\n%s", error, traceback.format_exc())
                    raise Exception("Error during extraction from url path")

            # create OrderedDict of positional argument
            positional = OrderedDict([(k, None) for k in insp.args])
            if insp.defaults is not None:
                positional.update(
                    dict(zip(insp.args[-len(insp.defaults):], insp.defaults))
                )
            positional.update(
                OrderedDict(
                    (k, _urlmatch.pop(k)) for k in insp.args if k in _urlmatch
                ),
                **OrderedDict(
                    (k, v) for k, v in parse_qsl if k in insp.args
                )
            )

            # create dict of non positional argument
            not_positional = dict(
                _urlmatch,
                **dict([(k, v) for k, v in parse_qsl if k not in insp.args])
            )

            # generate *args and **kwargs
            args = tuple(positional.values())
            kwargs = {} if insp.varargs is not None else not_positional
            if insp.keywords is not None:
                kwargs.update(
                    url=url, headers=headers, data=data, method=method
                )
            if insp.varargs is not None:
                args += (
                    (method, url, headers, data)
                    if insp.keywords is None else ()
                 ) + tuple(not_positional.values())

            return function(*args, **kwargs)

        # register wrapper in a container used to keep informations computed
        # during registration for future access
        container = Capsule(
            wrapper, wrapped=function.__name__, path=path, methods=methods,
            inspect=insp
        )

        if not hasattr(app, "ENDPOINTS"):
            setattr(app, "ENDPOINTS", {})
        # register wrapper in MicroJsonApp.ENDPOINTS
        for method in methods:
            if method not in app.ENDPOINTS:
                app.ENDPOINTS[method] = MatchDict()
            app.ENDPOINTS[method][path] = container
            LOGGER.debug(
                "%s bound to 'HTTP %s %s' request",
                function.__name__, method, path
            )
        return wrapper
    return decorator


def unbind(path, methods=["GET"], app=uroot.uRawHandler):
    for method in methods:
        if method in app.ENDPOINTS:
            app.ENDPOINTS[method]._matcher.pop(path, False)
            container = app.ENDPOINTS[method].pop(path, False)
            LOGGER.debug(
                "%s unbound from 'HTTP %s %s' request",
                container.func.__name__, method, path
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
        "-l", "--log-level", action="store", dest="loglevel", default=20,
        type="int",
        help="set log level from 1 to 50 [default: 20]"
    )
    parser.add_option(
        "-i", "--ip", action="store", dest="host", default="127.0.0.1",
        help="ip to run from             [default: 127.0.0.1]"
    )
    parser.add_option(
        "-p", "--port", action="store", dest="port", default=5000,
        type="int",
        help="port to use                [default: 5000]"
    )
    (options, args) = parser.parse_args()

    app = uJsonApp(options.host, options.port, loglevel=options.loglevel)

    # if no bindings, register few endpoints for testing purpose
    if len(args) == 0 and __name__ == "__main__":
        # url, headers, data and method loosed
        @bind("/", app=uJsonHandler)
        def test0(a, b=0):
            return a, b

        # get url, headers, data and method in args
        @bind("/vargs", app=uJsonHandler)
        def test1(a, b=1, *args):
            return (a, b) + args

        # get url, headers, data and method in kwargs
        @bind("/kwargs", app=uJsonHandler)
        def test2(a, b=2, **kwargs):
            return a, b, kwargs

        # get url, headers, data and method in kwargs
        @bind("/vargs_kwargs", app=uJsonHandler)
        def test3(a, b=3, *args, **kwargs):
            return (a, b) + args, kwargs

    else:
        for name in args:
            try:
                importlib.import_module(name)
            except ImportError as error:
                LOGGER.error("%r\n%s", error, traceback.format_exc())

    app.run(ssl=options.ssl)


if __name__ == "__main__":
    main()
