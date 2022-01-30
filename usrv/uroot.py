# -*- coding: utf-8 -*-
# © THOORENS Bruno

import os
import ssl
import json
import binascii
import mimetypes

from http.server import BaseHTTPRequestHandler
from urllib import parse


def context_call(cls, url, method, headers, data):
    path = parse.urlparse(url).path
    func = getattr(cls, "ENDPOINTS", {}).get(method, {}).get(path)
    if func is None:
        return 400, "no endpoind found behind %s" % url
    try:
        headers = dict([k.lower(), v] for k, v in dict(headers).items())
        if data not in [None, ""]:
            content_type = headers.get('content-type')
            if content_type == "application/json":
                data = json.loads(data)
            elif content_type == "application/x-www-form-urlencoded":
                data = dict(parse.parse_qsl(data))
        resp = func(method, url, headers, data)
        if isinstance(resp, tuple) and isinstance(resp[0], int):
            return resp
        else:
            return 200, resp
    except Exception as error:
        return 500, "%s raise an error: %r" % (func, error)


def wsgi_call(cls, environ, start_response):
    """
    Web Server Gateway Interface for deployment.
    https://www.python.org/dev/peps/pep-3333
    """
    method = environ["REQUEST_METHOD"]
    # handle HEAD specificity
    if method == "HEAD":
        func = getattr(cls, "ENDPOINTS", {}).get("HEAD").get(
            parse.quote(environ.get('PATH_INFO', ''))
        )
        if func is not None:
            data, content_type = cls.format_response("")
            start_response("200", (["Content-type", content_type],))(
                data.encode("latin-1") if not isinstance(data, bytes) else data
            )
        else:
            start_response("400")
        return b""

    http_input = ""
    if method not in ["GET", "DELETE", "OPTIONS", "TRACE"]:
        http_input = environ["wsgi.input"].read()
        if isinstance(http_input, bytes):
            http_input = http_input.decode("latin-1")

    status, resp = context_call(
        cls, wsgi_rebuild_url(environ), method, dict(
            [k.replace("HTTP_", "").replace("_", "-").lower(), v]
            for k, v in environ.items() if k.startswith("HTTP_")
        ), http_input
    )

    if status > 299:
        start_response("%d" % status)
        return b""

    data, content_type = cls.format_response(resp)

    start_response("%d" % status, (["Content-type", content_type],))(
        data.encode("latin-1") if not isinstance(data, bytes) else data
    )
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

    url += parse.quote(env.get('SCRIPT_NAME', ''))
    url += parse.quote(env.get('PATH_INFO', ''))

    if env.get('QUERY_STRING'):
        url += '?' + env['QUERY_STRING']

    return url


class uRawHandler(BaseHTTPRequestHandler):

    def __getattr__(self, attr):
        if attr.startswith("do_"):
            return lambda o=self: \
                self.__class__.do_(o, attr.replace("do_", ""))
        return BaseHTTPRequestHandler.__getattribute__(self, attr)

    @staticmethod
    def do_(self, method="GET"):
        # handle HEAD specificity
        if method == "HEAD":
            func = getattr(self.__class__, "ENDPOINTS", {}).get("HEAD").get(
                self.path.split("?")[0]
            )
            if func is not None:
                data, content_type = self.format_response("")
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-length', len(data))
                self.end_headers()
            else:
                self.send_error(400)
                self.end_headers()
            return

        http_input = ""
        # method bellow are not bodyless so read http_input
        if method not in ["GET", "DELETE", "OPTIONS", "TRACE"]:
            length = self.headers.get('content-length')
            http_input = self.rfile.read(
                int(length) if length is not None else 0
            )
            if isinstance(http_input, bytes):
                http_input = http_input.decode("latin-1")

        url = (
            "https://%s:%s%s" if isinstance(self.server.socket, ssl.SSLSocket)
            else "http://%s:%s%s"
        ) % (self.server.server_address + (self.path, ))

        status, resp = context_call(
            self.__class__, url, method, self.headers, http_input
        )

        if status > 299:
            self.send_error(status, explain=resp)
            self.end_headers()
            return

        data, content_type = self.__class__.format_response(resp)
        if isinstance(data, str):
            data = data.encode("latin-1")

        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-length', len(data))
        self.end_headers()
        return self.wfile.write(
            data if isinstance(data, bytes) else data.encode("latin-1")
        )

    @staticmethod
    def format_response(resp):
        return str(resp), "text/plain"


class FormData(list):
    """
    ~ [RFC#7578](https://datatracker.ietf.org/doc/html/rfc7578)
    Implementation of multipart/form-data encoder.
    """

    def append_json(self, name, value={}, **kwval):
        list.append(self, {
            "name": name,
            "data": json.dumps(
                dict(value, **kwval), sort_keys=True, separators=(",", ":")
            ).encode(),
            "headers": {"Content-Type": "application/json"}
        })
        return self

    def append_value(self, name, value, **headers):
        list.append(self, {
            "name": name,
            "data": value if isinstance(value, bytes) else (
                "%s" % value
            ).encode(),
            "headers": dict({"Content-Type": "plain/text"}, **headers)
        })
        return self

    def append_file(self, name, path):
        if os.path.isfile(path):
            list.append(self, {
                "name": name,
                "filename": os.path.basename(path),
                "headers": {
                    "Content-Type": (
                        mimetypes.guess_type(path)[0] or
                        "application/octet-stream"
                    )
                },
                "data": open(path, "rb").read()
            })
        else:
            raise IOError("file %s not found" % path)
        return self

    def encode(self):
        body = b""
        boundary = binascii.hexlify(os.urandom(16))

        for value in [dict(v) for v in self]:
            field = value.pop("name").encode()
            data = value.pop("data")
            headers = value.pop("headers")

            body += b'--' + boundary + b'\r\n'
            body += b'Content-Disposition: form-data; name="%s"; ' % field
            body += '; '.join(
                ['%s="%s"' % (n, v) for n, v in value.items()]
            ).encode() + b'\r\n'
            body += '\r\n'.join(
                ['%s: %s' % (n, v) for n, v in headers.items()]
            ).encode() + b'\r\n'
            body += b'\r\n' + data + b'\r\n'

        body += b'--' + boundary + b'--\r\n'
        return body, f"multipart/form-data; boundary={boundary.decode()}"

    @staticmethod
    def blind_encode(**fields):
        boundary = binascii.hexlify(os.urandom(16)).decode('ascii')
        body = (
            "".join(
                '--%s\r\n'
                'Content-Disposition: form-data; name="%s"\r\n'
                'Content-Type: text/plain; charset=UTF-8\r\n'
                '\r\n'
                '%s\r\n' % (
                    boundary, field, value
                ) for field, value in fields.items()
            ) + "--%s--\r\n" % boundary
        )
        return body, "multipart/form-data; boundary=%s" % boundary

    @staticmethod
    def loads(data):
        pass
