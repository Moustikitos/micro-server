# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
"""

import re
import os
import io
import ssl
import sys
import json
import logging
import binascii
import mimetypes

if sys.version_info[0] >= 3:
    from urllib.request import Request, OpenerDirector, HTTPHandler
    from urllib.request import HTTPSHandler, BaseHandler
    from urllib.parse import urlencode

else:
    from urllib2 import Request, OpenerDirector, HTTPHandler, HTTPSHandler
    from urllib2 import BaseHandler
    from urllib import urlencode

LOGGER = logging.getLogger("usrv.req")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class FormData(dict):
    """
    ~ [RFC#7578](https://datatracker.ietf.org/doc/html/rfc7578)
    Implementation of multipart form-data encoder.
    """

    def __setitem__(self, item, value):
        return self.append_value(item, value)

    def append_json(self, name, value={}, **kwval):
        dict.__setitem__(self, name, {
            "data": json.dumps(dict(value, **kwval), sort_keys=True).encode(),
            "headers": {"Content-Type": "application/json"}
        })
        return self

    def append_value(self, name, value, **headers):
        dict.__setitem__(self, name, {
            "data": value if isinstance(value, bytes) else (
                "%s" % value
            ).encode(),
            "headers": dict({"Content-Type": "plain/text"}, **headers)
        })
        return self

    def append_file(self, name, path):
        if os.path.isfile(path):
            data = io.open(path, "rb").read()
            dict.__setitem__(self, name, {
                "filename": os.path.basename(path),
                "headers": {
                    "Content-Type": (
                        mimetypes.guess_type(path)[0] or
                        "application/octet-stream"
                    )
                },
                "data": data
            })
        else:
            raise IOError("file %s not found" % path)
        return self

    def encode(self):
        body = b""
        boundary = binascii.hexlify(os.urandom(16))

        for field, _v in self.items():
            value = dict(_v)
            data = value.pop("data")
            headers = value.pop("headers")
            field = field.encode()

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


class EndPoint(object):

    timeout = 5
    opener = None
    peer = None
    startswith_ = re.compile(r"^_[0-9A-Fa-f].*")
    quiet = False

    def __init__(self, elem=None, parent=None, method=lambda: None):
        self.elem = elem
        self.parent = parent
        self.method = method

        if EndPoint.opener is None:
            EndPoint.opener = OpenerDirector()
            EndPoint.opener.add_handler(HTTPHandler())
            EndPoint.opener.add_handler(HTTPSHandler(context=CTX))

    def __getattr__(self, attr):
        if attr not in ["elem", "parent", "method", "chain"]:
            if EndPoint.startswith_.match(attr):
                attr = attr[1:]
            return EndPoint(attr, self, self.method)
        else:
            return object.__getattr__(self, attr)

    def __call__(self, *args, **kwargs):
        return self.method(*self.chain() + list(args), **kwargs)

    @staticmethod
    def _manage_response(res, error=None):
        text = res.read()
        try:
            data = json.loads(text)
        except Exception as err:
            data = {
                "success": True, "except": True,
                "raw":
                    text.decode("utf-8") if isinstance(text, bytes)
                    else text,
                "error": "%r" % err
            }
        if isinstance(data, dict):
            data["status"] = res.getcode()
        return data

    @staticmethod
    def _open(req):
        if req is False:
            return {"success": req}
        try:
            res = EndPoint.opener.open(req, timeout=EndPoint.timeout)
        except Exception as error:
            return {"success": False, "error": "%r" % error, "except": True}
        else:
            return EndPoint._manage_response(res)

    @staticmethod
    def _call(method="GET", *args, **kwargs):
        return EndPoint._open(EndPoint.build_req(method, *args, **kwargs))

    @staticmethod
    def build_req(method="GET", *args, **kwargs):
        method = method.upper()
        peer = kwargs.pop("peer", False) or EndPoint.peer
        headers = kwargs.pop("headers", {
            "Content-Type": "application/json",
            "User-agent": "Python/usrv"
        })
        to_multipart = kwargs.pop("_multipart", None)
        to_urlencode = kwargs.pop("_urlencode", None)
        to_jsonify = kwargs.pop("_jsonify", None)

        if not peer:
            if not EndPoint.quiet:
                raise Exception("No peer connection available")
            else:
                return False

        chain = ("/" + "/".join([a for a in args if a])).replace("//", "/")
        url = peer + chain

        if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
            if len(kwargs):
                url += "?" + urlencode(kwargs)
            req = Request(url, None, headers)
        else:
            # if data provided other than kwargs use kwargs to build url
            if any([to_urlencode, to_jsonify, to_multipart]):
                if len(kwargs):
                    url += "?" + urlencode(kwargs)
                # if explicitly asked to send data multipart/form-data
                if to_multipart is not None:
                    if isinstance(to_multipart, FormData):
                        data, headers["Content-Type"] = to_multipart.encode()
                    elif isinstance(to_multipart, dict):
                        data, headers["Content-Type"] = FormData.blind_encode(
                            **to_multipart
                        ).encode('utf-8')
                    else:
                        raise Exception(
                            "can not initialize multipart with %s" %
                            to_multipart
                        )
                # if explicitly asked to send data as urlencoded
                elif to_urlencode is not None:
                    headers["Content-Type"] = \
                        "application/x-www-form-urlencoded"
                    data = urlencode(to_urlencode).encode('utf-8')
                # if explicitly asked to send data as json
                elif to_jsonify is not None:
                    headers["Content-Type"] = "application/json"
                    data = json.dumps(to_jsonify).encode('utf-8')
            # if nothing provided send jsonified keywords as data
            else:
                headers["Content-Type"] = "application/json"
                data = json.dumps(kwargs).encode('utf-8')
            req = Request(url, data, headers)
        # tweak request
        req.get_method = lambda: method
        return req

    @staticmethod
    def connect(peer):
        try:
            EndPoint.opener.open(peer, timeout=EndPoint.timeout)
        except Exception:
            EndPoint.peer = None
            return False
        else:
            if peer.endswith("/"):
                peer = peer[:-1]
            EndPoint.peer = peer
            return True

    @staticmethod
    def disconnect():
        EndPoint.peer = None

    def add_handler(self, handler):
        if not isinstance(handler, BaseHandler):
            raise Exception(
                "%r have to be a %r instance" % (handler, BaseHandler)
            )
        if not isinstance(EndPoint.opener, OpenerDirector):
            EndPoint.opener = OpenerDirector()
        EndPoint.opener.add_handler(handler)

    def chain(self):
        return (self.parent.chain() + [self.elem]) if self.parent is not None \
               else [""]


def connect(peer):
    return EndPoint.connect(peer)


def disconnect():
    return EndPoint.disconnect()


CONNECT = EndPoint(method=lambda *a, **kw: EndPoint._call("CONNECT", *a, **kw))
DELETE = EndPoint(method=lambda *a, **kw: EndPoint._call("DELETE", *a, **kw))
GET = EndPoint(method=lambda *a, **kw: EndPoint._call("GET", *a, **kw))
HEAD = EndPoint(method=lambda *a, **kw: EndPoint._call("HEAD", *a, **kw))
OPTIONS = EndPoint(method=lambda *a, **kw: EndPoint._call("OPTIONS", *a, **kw))
PATCH = EndPoint(method=lambda *a, **kw: EndPoint._call("PATCH", *a, **kw))
POST = EndPoint(method=lambda *a, **kw: EndPoint._call("POST", *a, **kw))
PUT = EndPoint(method=lambda *a, **kw: EndPoint._call("PUT", *a, **kw))
TRACE = EndPoint(method=lambda *a, **kw: EndPoint._call("TRACE", *a, **kw))
