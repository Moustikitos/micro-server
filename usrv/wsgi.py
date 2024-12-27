# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
Web Server Gateway Interface (WSGI) for deployment.
This module provides the WSGI application interface as defined by PEP 3333.
It includes functions to handle incoming requests, map them to endpoints,
and format responses accordingly.

For more information, see: https://www.python.org/dev/peps/pep-3333
"""

import traceback
import urllib.parse as urlparse

from usrv import LOG
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler


def wsgi_call(
    cls: BaseHTTPRequestHandler, environ: dict, start_response: Callable
) -> bytes:
    """
    Process an incoming WSGI request and route it to the appropriate endpoint.

    Args:
        cls: The class handling the request, typically a subclass of
             BaseHTTPRequestHandler.
        environ: A dictionary containing CGI-like environment variables
                 for the request.
        start_response: A callable to start the HTTP response.

    Returns:
        bytes: The response body as bytes.
    """
    method = environ["REQUEST_METHOD"]
    # Read data from WSGI environment and decode it if it is bytes.
    http_input = environ["wsgi.input"].read()
    if isinstance(http_input, bytes):
        http_input = http_input.decode("latin-1")
    # Rebuild headers
    headers = dict(
        [k.replace("HTTP_", "").replace("_", "-").lower(), v]
        for k, v in environ.items() if k.startswith("HTTP_")
    )
    path = urlparse.quote(environ.get('PATH_INFO', ''))

    # Loop through registered endpoints for the given method.
    endpoints = getattr(cls, "ENDPOINTS", object())
    for regexp, callback in getattr(endpoints, method, {}).items():
        if regexp.match(path):
            try:
                status, *result = callback(
                    wsgi_rebuild_url(environ), headers, http_input or None
                )
            except TypeError as error:
                LOG.error(
                    f"python function {callback} did not return a valid "
                    f"response:\n{error}\n{traceback.format_exc()}"
                )
                start_response("406", ())
                return b""
            except Exception as error:
                LOG.error(
                    f"python function {callback} failed during execution:"
                    f"\n{error}\n{traceback.format_exc()}"
                )
                start_response("500", ())
                return b""

            if not isinstance(status, int):
                LOG.error(
                    f"first value returned by {callback} should be an "
                    "HTTP response status code (ie integer)"
                )
                start_response("406", ())
                return b""
            elif status >= 400:
                start_response(f"{status}", ())
                return b""
            else:
                data, content_type = cls.format_response(result)
                start_response(
                    f"{status}", (["Content-type", content_type],)
                )(
                    data if isinstance(data, bytes) else
                    data.encode("latin-1")
                )
            return b""
    # If the loop exits, then no endpoint was found.
    start_response("404", ())
    return b""


def wsgi_rebuild_url(env: dict) -> str:
    """
    Rebuild the full URL from the WSGI environment according to PEP #3333.

    Args:
        env: A dictionary containing WSGI environment variables.

    Returns:
        str: The fully reconstructed URL.
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

    url += urlparse.quote(env.get('SCRIPT_NAME', ''))
    url += urlparse.quote(env.get('PATH_INFO', ''))

    if env.get('QUERY_STRING', False):
        url += '?' + env['QUERY_STRING']

    return url
