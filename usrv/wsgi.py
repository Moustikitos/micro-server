# -*- coding: utf-8 -*-
# © THOORENS Bruno

import urllib.parse as urlparse


def wsgi_call(cls, environ, start_response):
    """
    Web Server Gateway Interface for deployment.
    https://www.python.org/dev/peps/pep-3333
    """
    method = environ["REQUEST_METHOD"]
    # handle HEAD specificity
    if method == "HEAD":
        for regexp, callback in getattr(cls.ENDPOINTS, "HEAD", {}).items():
            if regexp.match(urlparse.quote(environ.get('PATH_INFO', ''))):
                data, content_type = cls.format_response(None)
                start_response("200", (["Content-type", content_type],))(
                    data.encode("latin-1") if not isinstance(data, bytes)
                    else data
                )
                return b""
        start_response("404", {})
        return b""
    # read data from wsgi environ and decode it if it is bytes.
    http_input = environ["wsgi.input"].read()
    if isinstance(http_input, bytes):
        http_input = http_input.decode("latin-1")
    # rebuild url
    url = wsgi_rebuild_url(environ)
    # rebuild headers
    headers = dict(
        [k.replace("HTTP_", "").replace("_", "-").lower(), v]
        for k, v in environ.items() if k.startswith("HTTP_")
    )
    for regexp, callback in getattr(cls.ENDPOINTS,method, {}).items():
        if regexp.match(urlparse.quote(environ.get('PATH_INFO', ''))):
            if regexp.match(url):
                try:
                    result = callback(url, headers, http_input or None)
                    data, content_type = cls.format_response(result)
                    start_response("200", (["Content-type", content_type],))(
                        data.encode("latin-1") if not isinstance(data, bytes)
                        else data
                    )
                except Exception as error:
                    print(f"{error}")
                    start_response("500", {})
                return b""
    start_response("404", {})
    return b""


def wsgi_rebuild_url(env):
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

    url += urlparse.quote(env.get('SCRIPT_NAME', ''))
    url += urlparse.quote(env.get('PATH_INFO', ''))

    if env.get('QUERY_STRING', False):
        url += '?' + env['QUERY_STRING']

    return url
