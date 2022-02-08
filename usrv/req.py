# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
"""

import re
import ssl
import json
import logging

from usrv import uroot
from urllib.request import Request, OpenerDirector, HTTPHandler
from urllib.request import HTTPSHandler, BaseHandler
from urllib.parse import urlencode, parse_qsl


LOGGER = logging.getLogger("usrv.req")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


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
    def _manage_response(res):
        text = res.read()
        text = text.decode("latin-1") if isinstance(text, bytes) else text
        content_type = res.headers.get("content-type")
        try:
            if "application/json" in content_type:
                data = json.loads(text)
            elif "application/x-www-form-urlencoded" in content_type:
                data = dict(parse_qsl(text))
            else:
                data = {"raw": text}
        except Exception as err:
            data = {
                "except": True,
                "raw": text,
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
                    if isinstance(to_multipart, uroot.FormData):
                        data, headers["Content-Type"] = to_multipart.encode()
                    elif isinstance(to_multipart, dict):
                        data, headers["Content-Type"] = \
                            uroot.FormData.blind_encode(**to_multipart)
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
