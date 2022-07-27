# -*- coding: utf-8 -*-
# © THOORENS Bruno

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
        # initialize opener only once
        if EndPoint.opener is None:
            EndPoint.opener = OpenerDirector()
            EndPoint.opener.add_handler(HTTPHandler())
            EndPoint.opener.add_handler(HTTPSHandler(context=CTX))

    def __getattr__(self, attr):
        try:
            return object.__getattr__(self, attr)
        except AttributeError:
            if EndPoint.startswith_.match(attr):
                attr = attr[1:]
            return EndPoint(attr, self, self.method)

    def __call__(self, *args, **kwargs):
        return self.method(*self.chain() + list(args), **kwargs)

    @staticmethod
    def _manage_response(res):
        content_type = res.headers.get("content-type")
        text = res.read()
        if isinstance(text, bytes):
            text = text.decode(res.headers.get_content_charset("latin-1"))
        if content_type is not None:
            if "application/json" in content_type:
                data = json.loads(text)
            elif "application/x-www-form-urlencoded" in content_type:
                data = dict(parse_qsl(text))
            else:
                data = {"raw": text}
        else:
            data = {"raw": text}

        if isinstance(data, dict) and "status" not in data:
            data["status"] = res.getcode()
        return data

    @staticmethod
    def _open(req):
        if not isinstance(req, Request):
            LOGGER.error("it seems request is not build properly")
            return {
                "success": False, "req": "%s" % req, "except": True,
                "where": "_open", "status": 500,
                "msg": "it seems request is not build properly"
            }
        try:
            res = EndPoint.opener.open(req, timeout=EndPoint.timeout)
        except Exception as error:
            LOGGER.error("%r", error)
            return {
                "success": False, "error": "%r" % error, "except": True,
                "where": "_open", "status": 500
            }
        else:
            return EndPoint._manage_response(res)

    @staticmethod
    def _call(method="GET", *args, **kwargs):
        try:
            return EndPoint._open(EndPoint.build_req(method, *args, **kwargs))
        except Exception as error:
            LOGGER.error("internal error occured on request building")
            return {
                "success": False, "error": "%r" % error, "except": True,
                "where": "_call", "status": 500,
                "msg": "internal error occured on request building"
            }

    @staticmethod
    def build_req(method="GET", *args, **kwargs):
        # build headers
        headers = dict({
            "Content-type": "application/json",
            "User-agent": "Python/usrv"
        }, **dict(
            (k.capitalize(), v)
            for k, v in kwargs.pop("headers", {}).items()
        ))
        method = method.upper()
        peer = kwargs.pop("peer", False) or EndPoint.peer
        to_multipart = kwargs.pop("_multipart", None)
        to_urlencode = kwargs.pop("_urlencode", None)
        to_jsonify = kwargs.pop("_jsonify", None)

        if not peer:
            if not EndPoint.quiet:
                raise Exception("No peer connection available")
            else:
                LOGGER.info("No peer connection available")
                return False
        # buid request
        chain = ("/" + "/".join([a for a in args if a])).replace("//", "/")
        req = Request(peer + chain, None, headers)
        # transform kwargs into query string if bodyless method used
        if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
            if len(kwargs):
                req.full_url = req.full_url + "?" + urlencode(kwargs)
        else:
            content_type = req.headers.get("Content-type", "").split(";")
            if len(content_type) > 1:
                content_type, encoding = content_type
                key, value = encoding.split("=")
                # key coud be 'charset' or 'boundary'
                if key.lower() == "charset":
                    encoding = value.strip()
                else:
                    encoding = "latin-1"
            else:
                content_type, encoding = content_type[0], "latin-1"
            if any([to_urlencode, to_jsonify, to_multipart]):
                # if data provided other than kwargs use kwargs to build
                # query string
                if len(kwargs):
                    req.full_url = req.full_url + "?" + urlencode(kwargs)
                # if explicitly asked to send data multipart/form-data
                if to_multipart is not None:
                    if isinstance(to_multipart, uroot.FormData):
                        data, content_type = to_multipart.encode()
                    elif isinstance(to_multipart, dict):
                        data, content_type = \
                            uroot.FormData.blind_encode(**to_multipart)
                    else:
                        raise Exception(
                            "can not initialize multipart with %s" %
                            to_multipart
                        )
                # if explicitly asked to send data as urlencoded
                elif to_urlencode is not None:
                    data = urlencode(to_urlencode)
                    content_type = "application/x-www-form-urlencoded"
                # if explicitly asked to send data as json
                elif to_jsonify is not None:
                    data = json.dumps(to_jsonify)
                    content_type = "application/json"
            # if nothing provided send jsonified keywords as data
            elif content_type == "application/json":
                data = json.dumps(kwargs)
            elif kwargs:
                data = str(kwargs)
            else:
                data = ""
            # set data and content-type header
            req.data = data.encode(encoding)
            req.add_header(
                "content-type", f"{content_type}; charset={encoding}"
            )
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
