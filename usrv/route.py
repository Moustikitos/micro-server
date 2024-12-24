# -*- coding: utf-8 -*-
# © THOORENS Bruno

import re
import ssl
import json
import typing
import inspect

import urllib.parse as urlparse

from usrv import LOG
from collections.abc import Callable
from collections import OrderedDict, namedtuple
from http.server import BaseHTTPRequestHandler

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
                    result = callback(url, headers, http_input or None)
                    self.send_response(200)
                except Exception as error:
                    LOG.exception(f"{error}")
                    self.send_error(500)
                    result = None
                data, content_type = self.format_response(result)
                if isinstance(data, str):
                    data = data.encode("latin-1")
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
                lambda url, headers, data, \
                    f=function, m=markups, r=regexp, a=arg_spec:\
                    callback(url, headers, data, f, m, r, a)
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
    positional.update(
        OrderedDict([k, v] for k, v in parse_qsl if k in arg_spec.args),
        **OrderedDict([k, v] for k, v in params.items() if k in arg_spec.args)
    )
    # build *args and **kwargs for function call 
    args = tuple(positional.values())
    kwargs = {}
    if arg_spec.varkw is not None:
        kwargs.update(
            dict([k, v] for k, v in parse_qsl if k not in arg_spec.args),
            headers = headers, data=data,
            **dict([k, v] for k, v in params.items() if k not in arg_spec.args)
        )
    elif arg_spec.varargs is not None:
        args += tuple(v for k, v in parse_qsl if k not in arg_spec.args) + \
            tuple(v for k, v in params.items() if k not in arg_spec.args) + \
            (headers, data)
    return function(*args, **kwargs)


if __name__ == "__main__":
    from http.server import HTTPServer

    # url, headers, data and method loosed
    @bind("/")
    def test0(a, b=0):
        return a, b

    # get url, headers, data and method in args
    @bind("/<float:c>/vargs")
    def test1(a, b=1, c=0, *args):
        return (a, b, c) + args

    # get url, headers, data and method in kwargs
    @bind("/<name>/kwargs")
    def test2(a, b=2, **kwargs):
        return a, b, kwargs

    # get url, headers, data and method in kwargs
    @bind("/<name>/<int:c>/vargs_kwargs")
    def test3(a, b=2, *args, **kwargs):
        return a, b, args, kwargs


    httpd = HTTPServer(("127.0.0.1", 5000), uHTTPRequestHandler)
    LOG.setLevel(20)
    try:
        LOG.info(
            "listening on %s:%s\nCTRL+C to stop..." % 
            ("http://127.0.0.1", 5000)
        )
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("server stopped")
