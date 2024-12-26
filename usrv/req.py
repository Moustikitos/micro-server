# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
# HTTP Client Module

This module provides a flexible and extensible framework for building, sending,
and managing HTTP requests and responses. It includes support for dynamic
endpoints, SSL configuration, and content decoding based on MIME types.

## Classes
  - Endpoint: Represents an HTTP endpoint with dynamic attribute handling and
    customizable request methods.

## Functions
  - build_request: Constructs HTTP requests with specified parameters and
    headers.
  - manage_response: Parses and decodes HTTP responses based on their MIME
    types.

## Constants
  - CONTEXT: SSL context with disabled hostname verification.
  - DECODERS: Dictionary mapping MIME types to their respective parsers.
  - OPENER: Global HTTP request opener.

## Endpoints
Predefined instances of the `Endpoint` class for standard HTTP methods:
  - CONNECT
  - GET
  - HEAD
  - OPTION
  - PATCH
  - POST
  - PUT
  - TRACE
  - DELETE

This module is designed to handle common HTTP operations in a clean and
reusable manner, with dynamic endpoint resolution and robust response
management.
"""

import re
import ssl
import json
import typing
import traceback

from usrv import LOG
from collections.abc import Callable
from urllib.request import Request, OpenerDirector, HTTPHandler
from urllib.request import HTTPSHandler, FileHandler
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
from http.client import HTTPResponse
from collections import namedtuple

# namedtuple to match the internal signature of urlunparse
Urltuple = namedtuple(
    typename='Urltuple', field_names=[
        'scheme', 'netloc', 'path', 'params', 'query', 'fragment'
    ]
)

CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE

DECODERS = {
    "application/x-www-form-urlencoded": parse_qsl,
    "application/json": json.loads
}

OPENER = OpenerDirector()
OPENER.add_handler(HTTPHandler())
OPENER.add_handler(HTTPSHandler(context=CONTEXT))
OPENER.add_handler(FileHandler())


def build_request(method: str = "GET", path: str = "/", **kwargs) -> Request:
    """
    Builds an HTTP request object.

    Args:
        method (str): HTTP method (e.g., 'GET', 'POST'). Defaults to 'GET'.
        path (str): URL path for the request. Defaults to '/'.
        **kwargs: Additional keyword arguments for query parameters, headers,
            and data.

    Returns:
        Request: Configured HTTP request object.
    """
    encoder = kwargs.pop("encoder", urlencode)
    peer = kwargs.pop("peer", False) or Endpoint.peer
    headers = kwargs.pop("headers", {"User-Agent": "Python/usrv"})
    method = method.upper()

    if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
        query = urlencode(kwargs)
        data = None
    else:
        query = None
        data = encoder(**kwargs)

    headers["Content-Type"] = \
        "application/x-www-form-urlencoded" if encoder == urlencode else \
        "application/json"

    req = Request(
        urlunparse(urlparse(peer)._replace(path=path, query=query)),
        data, headers
    )
    req.get_method = lambda: method
    return req


def manage_response(resp: HTTPResponse) -> typing.Union[dict, str]:
    """
    Parses the HTTP response.

    Args:
        resp (HTTPResponse): HTTP response object.

    Returns:
        typing.Union[dict, str]: Decoded response content.
    """
    content_type = resp.headers.get("content-type").lower()
    text = resp.read()
    text = text.decode(resp.headers.get_content_charset("latin-1")) \
        if isinstance(text, bytes) else text

    if "text/" not in content_type:
        text = DECODERS[content_type.split(";")[0].strip()](text)

    return text


class Endpoint:
    """
    Represents an HTTP endpoint with dynamic attribute handling.

    Attributes:
        startswith_ (re.Pattern): Pattern to match internal attributes.
        timeout (int): Default timeout for requests.
        opener (OpenerDirector): Opener to handle HTTP requests.
        peer (str): Base URL for the endpoint.
    """

    startswith_ = re.compile(r"^_[0-9].*")
    timeout = 5
    opener = None
    peer = None

    def __init__(
        self, master: typing.Any = None, name: str = "",
        method: Callable = build_request
    ):
        """
        Initializes an Endpoint instance.

        Args:
            master (typing.Any): Parent endpoint.
            name (str): Name of the current endpoint.
            method (Callable): Request-building method.
        """
        if master is None:
            self.path = name
        else:
            self.path = f"{master.path}/{name}"
        self.method = method

    def __getattr__(self, attr: str):
        """
        Dynamically resolves sub-endpoints.

        Args:
            attr (str): Attribute name.

        Returns:
            Endpoint: New sub-endpoint instance.
        """
        try:
            return Endpoint.__getattribute__(self, attr)
        except AttributeError:
            if Endpoint.startswith_.match(attr):
                attr = attr[1:]
            return Endpoint(self, attr, self.method)

    def __call__(self, **kwargs):
        """
        Executes the endpoint's method with provided arguments.

        Args:
            **kwargs: Parameters for the HTTP request.

        Returns:
            Request: Configured HTTP request.
        """
        return self.method(self.path, **kwargs)

    @staticmethod
    def connect(peer: str):
        """
        Tests connection to a peer endpoint and store it if success.

        Args:
            peer (str): Peer URL to test.

        Returns:
            typing.Union[int, bool]: HTTP status code or False on failure.
        """
        try:
            res = OPENER.open(
                build_request("HEAD", peer=peer), timeout=Endpoint.timeout
            )
        except Exception as error:
            LOG.error("%r\n%s", error, traceback.format_exc())
        else:
            Endpoint.peer = peer
            return res.status
        return False


# HTTP method endpoints
CONNECT = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("CONNECT", url, encoder=json.dumps, **parameters)
        )
    )
)

GET = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("GET", url, encoder=json.dumps, **parameters)
        )
    )
)

HEAD = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("HEAD", url, encoder=json.dumps, **parameters)
        )
    )
)

OPTION = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("HEAD", url, encoder=json.dumps, **parameters)
        )
    )
)

PATCH = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("PATCH", url, encoder=json.dumps, **parameters)
        )
    )
)

POST = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("POST", url, encoder=json.dumps, **parameters)
        )
    )
)

PUT = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("PUT", url, encoder=json.dumps, **parameters)
        )
    )
)

TRACE = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("TRACE", url, encoder=json.dumps, **parameters)
        )
    )
)

DELETE = Endpoint(
    method=lambda url, **parameters: manage_response(
        OPENER.open(
            build_request("DELETE", url, encoder=json.dumps, **parameters)
        )
    )
)
