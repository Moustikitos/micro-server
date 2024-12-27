# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
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
"""

import re
import ssl
import sys
import json
import typing
import inspect
import builtins
import traceback

import urllib.parse as urlparse

from usrv import LOG
from collections.abc import Callable
from collections import OrderedDict, namedtuple
from http.server import BaseHTTPRequestHandler, HTTPServer

# Regex for extracting dynamic segments from URLs.
MARKUP_PATTERN = re.compile("<([^><]*)>")
# Named tuple for representing argument specifications.
FixArgSpec = namedtuple(
    "FixArgSpec", (
        'args', 'varargs', 'varkw', 'defaults', 'kwonlyargs',
        'kwonlydefaults', 'annotations', "keywords"
    )
)


class Endpoint:
    """Placeholder for storing endpoint mappings."""
    pass


class EndpointAlreadyDefined(Exception):
    """Exception raised when an endpoint is already defined."""
    pass


class UrlMatchError(Exception):
    """Exception raised for errors in URL pattern matching."""
    pass


class uHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler that handles HTTP methods dynamically.

    Methods:
        format_response: Formats the response as JSON.
        do_: Processes HTTP requests based on registered endpoints.
    """

    def __getattr__(self, attr: str) -> Callable:
        """
        Dynamically handles HTTP methods like 'do_GET', 'do_POST', etc.

        Args:
            attr (str): The attribute name.

        Returns:
            Callable: The dynamic handler function.
        """
        if attr.startswith("do_"):
            return lambda o=self: \
                self.__class__.do_(o, method=attr.replace("do_", ""))
        return BaseHTTPRequestHandler.__getattribute__(self, attr)

    @staticmethod
    def format_response(resp: typing.Any) -> typing.Tuple[str, str]:
        """
        Formats a response as JSON.

        Args:
            resp (Any): The response data.

        Returns:
            Tuple[str, str]: The JSON response and its content type.
        """
        return json.dumps(resp), "application/json"

    def do_(self, method: str = "GET") -> int:
        """
        Processes an HTTP request and calls the appropriate endpoint.

        Args:
            method (str): The HTTP method (e.g., "GET", "POST").
                          Defaults to "GET".

        Returns:
            int: Status code of the response.
        """
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

        # Loop through registered endpoints for the given method.
        endpoints = getattr(uHTTPRequestHandler, "ENDPOINTS", object())
        for regexp, callback in getattr(endpoints, method, {}).items():
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
def _get_arg_spec(function: Callable) -> FixArgSpec:
    """
    Retrieves the argument specification of a function.

    Args:
        function (Callable): The function to inspect.

    Returns:
        FixArgSpec: Named tuple containing function argument details.
    """
    insp = inspect.getfullargspec(function)
    return FixArgSpec(**dict(insp._asdict(), keywords=insp.varkw))


def bind(
    path: str, methods: list = ["GET"],
    target: BaseHTTPRequestHandler = uHTTPRequestHandler
) -> Callable:
    """
    Binds a function to a specific URL path and HTTP methods.

    Args:
        path (str): The URL path to bind.
        methods (list): List of HTTP methods (e.g., ["GET", "POST"]).
        target (BaseHTTPRequestHandler): The request handler class.

    Returns:
        Callable: A decorator that binds the function.
    """
    # Normalize the path.
    if path != '/':
        if path[0] != '/':
            path = '/' + path
        if path.endswith("/"):
            path = path[:-1]

    if not hasattr(target, "ENDPOINTS"):
        setattr(target, "ENDPOINTS", Endpoint())

    def decorator(function: Callable):
        """
        Decorator to register the function as an endpoint.

        Args:
            function (Callable): The function to register.
        """
        # Create a regex replacing all dynamic segments in the path.
        # '/person/<name>/<int:age>' --> '/person/([^/])*/([^/]*)'
        regexp = re.compile(f"^{MARKUP_PATTERN.sub('([^/]*)', path)}$")
        # Extract dynamic segments from the path.
        markups = MARKUP_PATTERN.findall(path)
        # markup pattern could be 'name' or 'type:name'
        # 'name'.split(":") == ["name"]
        # 'type:name'.split(":") == ["type", "name"]
        # tn[-1] == "name"
        # args is a dict([('name', type)...])
        markups = OrderedDict(
            [tn[-1], getattr(builtins, tn[0], str)] for tn in [
                elem.split(":") for elem in markups
            ]
        )
        # Inspect the function to get its argument specification.
        arg_spec = _get_arg_spec(function)
        # Create endpoints for each HTTP method.
        for method in methods:
            # create method dict in ENDPOINTS class of target
            if not hasattr(target.ENDPOINTS, method):
                setattr(target.ENDPOINTS, method, {})
            # raise Exception if regexp already set
            if regexp in getattr(target.ENDPOINTS, method):
                raise EndpointAlreadyDefined(f"{path} regexp already set")
            # set regexp - callback pair
            getattr(target.ENDPOINTS, method)[regexp] = \
                lambda url, headers, data, f=function, m=method, v=markups, \
                r=regexp, a=arg_spec: \
                callback(url, headers, data, f, m, v, r, a)
    return decorator


def callback(
    url: str, headers: dict, data: str, function: Callable, method: str,
    markups: OrderedDict, regexp: re.Pattern, arg_spec: inspect.FullArgSpec,
) -> typing.Any:
    """
    Handles the execution of the bound function with appropriate arguments.
    the last 4 parameters are defined by the bind function and stored in the
    lambda callback.

    Args:
        url (str): The full URL of the request.
        headers (dict): The HTTP headers from the request.
        data (str): The body of the request.
        function (Callable): The function to execute.
        method (str): The HTTP command used.
        markups (OrderedDict): Mappings of path variables to their types.
        regexp (re.Pattern): Compiled regex for path matching.
        arg_spec (FixArgSpec): Argument specification of the function.

    Returns:
        Any: The result of the function execution.
    """
    # Parse the URL to extract path and query parameters.
    parse = urlparse.urlparse(url)
    parse_qsl = urlparse.parse_qsl(parse.query)
    # Build parameters from URL path variables.
    params = {}
    try:
        for (name, typ_), value in zip(
            markups.items(), regexp.match(parse.path).groups()
        ):
            params[name] = typ_(value)
    except Exception as error:
        raise UrlMatchError(f"error occured on parsnig URL:\n{error}")
    # Create positional arguments with defaults.
    positional = OrderedDict([arg, None] for arg in arg_spec.args)
    # update it with default values if any
    if arg_spec.defaults is not None:
        positional.update(
            dict(
                zip(arg_spec.args[-len(arg_spec.defaults):], arg_spec.defaults)
            )
        )
    # Update positional arguments with parameters from the query string.
    parse_qsl = tuple([k, v] for k, v in parse_qsl if k not in params)
    positional.update(
        OrderedDict([k, v] for k, v in params.items() if k in arg_spec.args),
        **OrderedDict([k, v] for k, v in parse_qsl if k in arg_spec.args)
    )
    # Build *args and **kwargs for the function call.
    args = tuple(positional.values())
    kwargs = OrderedDict()
    if arg_spec.varkw is not None:
        kwargs.update(
            dict([k, v] for k, v in parse_qsl if k not in arg_spec.args),
            **dict([k, v] for k, v in params.items() if k not in arg_spec.args)
        )
        kwargs.update(method=method, headers=headers, data=data)
    elif arg_spec.varargs is not None:
        args += tuple(v for k, v in parse_qsl if k not in arg_spec.args) + \
            tuple(v for k, v in params.items() if k not in arg_spec.args) + \
            (method, headers, data)
    return function(*args, **kwargs)


def run(host: str = "127.0.0.1", port: int = 5000, loglevel: int = 20) -> None:
    """
    Starts the HTTP server.

    Args:
        host (str): The IP address to bind to. Defaults to "127.0.0.1".
        port (int): The port to bind to. Defaults to 5000.
        loglevel (int): Logging level. Defaults to 20.
    """
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

    # Parse command-line arguments.
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

    # If no modules are specified in the command line, register default routes.
    if len(args) == 0:
        # Default route for testing without arguments.
        @bind("/")
        def test0() -> tuple:
            """
            A test endpoint that returns a success message.

            Returns:
                tuple: HTTP status code and response body.
            """
            return 200, "Test page"

        # Test route demonstrating *args handling.
        @bind("/vargs")
        def test1(a, b=1, c=0, *args) -> tuple:
            """
            A test endpoint to demonstrate positional arguments.

            Args:
                a: First argument.
                b: Second argument (default=1).
                c: Third argument (default=0).
                *args: Additional positional arguments.

            Returns:
                tuple: HTTP status code and the received arguments.
            """
            return 200, a, b, c, args

        # Test route demonstrating **kwargs handling.
        @bind("/kwargs")
        def test2(name, a, b=2, **kwargs) -> tuple:
            """
            A test endpoint to demonstrate keyword arguments.

            Args:
                name: Name parameter.
                a: Parameter a.
                b: Parameter b (default=2).
                **kwargs: Additional keyword arguments.

            Returns:
                tuple: HTTP status code and the received arguments.
            """
            return 200, name, a, b, kwargs

        # Test route demonstrating an error with status 406.
        @bind("/error_406")
        def test3(a, b=2, *args, **kwargs) -> tuple:
            """
            A test endpoint that returns a 406 error.

            Args:
                a: First parameter.
                b: Second parameter (default=2).
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.

            Returns:
                tuple: received arguments without status code.
            """
            return a, b, args, kwargs

        # Test route demonstrating a server-side error.
        @bind("/error_500")
        def test4(a, b=2, *args, **kwargs) -> None:
            """
            A test endpoint that raises an exception.

            Args:
                a: First parameter.
                b: Second parameter (default=2).
                *args: Additional positional arguments.
                **kwargs: Additional keyword arguments.

            Raises:
                Exception: Simulates a server-side error.
            """
            raise Exception

    else:
        # Dynamically import modules specified in the command line.
        for name in args:
            try:
                importlib.import_module(name)
            except ModuleNotFoundError:
                LOG.error(
                    f"module {name} not found in path:\n"
                    f"{'\n    '.join(sys.path)}"
                )
            except ImportError as error:
                LOG.error("%r\n%s", error, traceback.format_exc())

    # Start the server with the specified options.
    run(options.host, options.port, options.loglevel)
