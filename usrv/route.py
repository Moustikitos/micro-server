# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module contains all the utilities to launch a micro server (ie, you get
and send json) from python lib or WGSI (highly recommended in production mode).

```bash
$ python route.py -h
Usage: route.py [options] BINDINGS...

Options:
  -h, --help            show this help message and exit
  -l LOGLEVEL, --log-level=LOGLEVEL
                        set log level from 1 to 50 [default: 20]
  -i HOST, --ip=HOST    ip to run from             [default: 127.0.0.1]
  -p PORT, --port=PORT  port to use                [default: 5000]
```

`BINDINGS` is a list of python modules containing python bound functions.
"""

import re
import ssl
import json
import typing
import inspect
import traceback

import urllib.parse as urlparse

from usrv import LOG
from collections.abc import Callable
from collections import OrderedDict, namedtuple
from http.server import BaseHTTPRequestHandler, HTTPServer

MARKUP_PATTERN = re.compile("<([^><]*)>")
FixArgSpec = namedtuple(
    "FixArgSpec", (
        'args', 'varargs', 'varkw', 'defaults', 'kwonlyargs',
        'kwonlydefaults', 'annotations', "keywords"
    )
)


class Endpoint:
    pass


class EndpointAlreadyDefined(Exception):
    pass


class UrlMatchError(Exception):
    pass


class uHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler with all HTTP request defined.
    """

    def __getattr__(self, attr):
        if attr.startswith("do_"):
            return lambda o=self: \
                self.__class__.do_(o, method=attr.replace("do_", ""))
        return BaseHTTPRequestHandler.__getattribute__(self, attr)

    @staticmethod
    def format_response(resp):
        return json.dumps(resp), "application/json"

    def do_(self, method: str = "GET") -> int:
        length = self.headers.get('content-length')
        http_input = self.rfile.read(int(length) if length is not None else 0)
        if isinstance(http_input, bytes):
            http_input = http_input.decode(
                self.headers.get_content_charset("latin-1")
            )
        url = (
            "https://%s:%s%s" if isinstance(self.server.socket, ssl.SSLSocket)
            else "http://%s:%s%s"
        ) % (self.server.server_address + (self.path, ))
        headers = dict([k.lower(), v] for k, v in dict(self.headers).items())
        path = urlparse.urlparse(self.path).path
        for regexp, callback in uHTTPRequestHandler.ENDPOINTS.GET.items():
            if regexp.match(path):
                try:
                    status, *result = callback(
                        url, headers, http_input or None
                    )
                except TypeError as error:
                    LOG.error(
                        f"python function {callback} did not return a valid "
                        f"response:\n{error}\n{traceback.format_exc()}"
                    )
                    self.send_error(406)
                    self.end_headers()
                except Exception as error:
                    LOG.error(
                        f"python function {callback} failed during execution:"
                        f"\n{error}\n{traceback.format_exc()}"
                    )
                    self.send_error(500)
                    self.end_headers()
                    return 0

                if not isinstance(status, int):
                    LOG.error(
                        f"first value returned by {callback} should be an "
                        "HTTP response status code (ie integer)"
                    )
                    self.send_error(406)
                    self.end_headers()
                    return 0
                elif status >= 400:
                    self.send_error(status)
                    self.end_headers()
                    return 0
                else:
                    data, content_type = self.format_response(result)
                    if isinstance(data, str):
                        data = data.encode("latin-1")
                    self.send_response(status)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-length', len(data))
                    self.end_headers()
                    return self.wfile.write(data)
        # if for loop exit, then no endpoint found
        self.send_error(404)
        self.end_headers()
        return 0


# function inspector
def _get_arg_spec(function) -> FixArgSpec:
    insp = inspect.getfullargspec(function)
    return FixArgSpec(**dict(insp._asdict(), keywords=insp.varkw))


def bind(
    path: str, methods: list = ["GET"],
    target: BaseHTTPRequestHandler = uHTTPRequestHandler
) -> Callable:
    # normalize path
    if path != '/':
        if path[0] != '/':
            path = '/' + path
        if path.endswith("/"):
            path = path[:-1]

    if not hasattr(target, "ENDPOINTS"):
        setattr(target, "ENDPOINTS", Endpoint())

    def decorator(function: Callable):
        # create a regexp replacing all markup by '([^/]*)'
        # '/person/<name>/<int:age>' --> '/person/([^/])*/([^/]*)'
        regexp = re.compile(f"^{MARKUP_PATTERN.sub('([^/]*)', path)}$")
        # extract markups from path
        markups = MARKUP_PATTERN.findall(path)
        # markup pattern could be 'name' or 'type:name'
        # 'name'.split(":") == ["name"]
        # 'type:name'.split(":") == ["type", "name"]
        # tn[-1] == "name"
        # args is a dict([('name', type)...])
        markups = OrderedDict(
            [tn[-1], getattr(__builtins__, tn[0], str)] for tn in [
                elem.split(":") for elem in markups
            ]
        )
        # inspect function
        arg_spec = _get_arg_spec(function)
        # create endpoints
        for method in methods:
            # create method dict in ENDPOINTS class of target
            if not hasattr(target.ENDPOINTS, method):
                setattr(target.ENDPOINTS, method, {})
            # raise Exception if regexp already set
            if regexp in getattr(target.ENDPOINTS, method):
                raise EndpointAlreadyDefined(f"{path} regexp already set")
            # set regexp - callback pair
            getattr(target.ENDPOINTS, method)[regexp] = \
                lambda url, headers, data, f=function, m=markups, r=regexp, \
                a=arg_spec: callback(url, headers, data, f, m, r, a)
    return decorator


def callback(
    url: str, headers: dict, data: str, function: Callable,
    markups: OrderedDict, regexp: re.Pattern, arg_spec: inspect.FullArgSpec,
) -> typing.Any:
    """
    """
    # get path and query from url
    parse = urlparse.urlparse(url)
    parse_qsl = urlparse.parse_qsl(parse.query)
    # build parameters
    params = {}
    try:
        for (name, typ_), value in zip(
            markups.items(), regexp.match(parse.path).groups()
        ):
            params[name] = typ_(value)
    except Exception as error:
        raise UrlMatchError(f"error occured on parsnig URL:\n{error}")
    # create a void OrderedDict of positional argument
    positional = OrderedDict([arg, None] for arg in arg_spec.args)
    # update it with default values if any
    if arg_spec.defaults is not None:
        positional.update(
            dict(
                zip(arg_spec.args[-len(arg_spec.defaults):], arg_spec.defaults)
            )
        )
    # update with what is found in url querry string and then in url path so
    # typing is preserved
    parse_qsl = tuple([k, v] for k, v in parse_qsl if k not in params)
    positional.update(
        OrderedDict([k, v] for k, v in params.items() if k in arg_spec.args),
        **OrderedDict([k, v] for k, v in parse_qsl if k in arg_spec.args)
    )
    # build *args and **kwargs for function call
    args = tuple(positional.values())
    kwargs = OrderedDict()
    if arg_spec.varkw is not None:
        kwargs.update(
            dict([k, v] for k, v in parse_qsl if k not in arg_spec.args),
            **dict([k, v] for k, v in params.items() if k not in arg_spec.args)
        )
        kwargs.update(headers=headers, data=data)
    elif arg_spec.varargs is not None:
        args += tuple(v for k, v in parse_qsl if k not in arg_spec.args) + \
            tuple(v for k, v in params.items() if k not in arg_spec.args) + \
            (headers, data)
    return function(*args, **kwargs)


def run(host: str = "127.0.0.1", port: int = 5000, loglevel: int = 20) -> None:
    LOG.setLevel(20)
    httpd = HTTPServer((host, port), uHTTPRequestHandler)
    try:
        LOG.info("listening on %s:%s\nCTRL+C to stop...", host, port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("server stopped")


if __name__ == "__main__":
    import importlib
    from optparse import OptionParser

    parser = OptionParser(
        usage="usage: %prog [options] BINDINGS...",
        version="%prog 1.0"
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

    if len(args) == 0:
        # url, headers, data and method loosed
        @bind("/")
        def test0(a, b=0):
            return 200, a, b
        # get url, headers, data and method in args

        @bind("/<float:c>/vargs")
        def test1(a, b=1, c=0, *args):
            return 200, (a, b, c) + args
        # get url, headers, data and method in kwargs

        @bind("/<name>/kwargs")
        def test2(name, a, b=2, **kwargs):
            return 200, name, a, b, kwargs
        # get url, headers, data and method in kwargs

        @bind("/406_error")
        def test4(a, b=2, *args, **kwargs):
            return a, b, args, kwargs

    else:
        for name in args:
            try:
                importlib.import_module(name)
            except ImportError as error:
                LOG.error("%r\n%s", error, traceback.format_exc())

    run(options.host, options.port, options.loglevel)
