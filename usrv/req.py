# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
"""

import re
import sys
import json
import logging

if sys.version_info[0] >= 3:
    from urllib.request import Request, OpenerDirector, HTTPHandler
    from urllib.request import HTTPSHandler, BaseHandler
    from urllib.parse import urlencode

else:
    from urllib2 import Request, OpenerDirector, HTTPHandler, HTTPSHandler
    from urllib2 import BaseHandler
    from urllib import urlencode

LOGGER = logging.getLogger("usrv.req")


def connect(peer):
    return EndPoint.connect(peer)


def disconnect():
    return EndPoint.disconnect()


class EndPoint(object):

    timeout = 5
    opener = None
    peer = None
    startswith_ = re.compile(r"^_[0-9A-Fa-f].*")

    def __init__(self, elem=None, parent=None, method=lambda: None):
        self.elem = elem
        self.parent = parent
        self.method = method

        if EndPoint.opener is None:
            EndPoint.opener = OpenerDirector()
            for handler in [HTTPHandler, HTTPSHandler]:
                EndPoint.opener.add_handler(handler())

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
        headers = kwargs.pop("headers", {
            "Content-type": "application/json",
            "User-agent": "Python/usrv"
        })
        to_urlencode = kwargs.pop("urlencode", None)
        to_jsonify = kwargs.pop("jsonify", None)

        # construct base url
        chain = "/".join([a for a in args if a])
        if not chain.startswith("/"):
            chain = "/" + chain
        else:
            chain = chain.replace("//", "/")
        peer = kwargs.pop("peer", False) or EndPoint.peer
        if peer in [False, None]:
            raise Exception("No peer connection available")
        url = peer + chain

        if method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
            if len(kwargs):
                url += "?" + urlencode(kwargs)
            req = Request(url, None, headers)
        else:
            # if data provided other than kwargs use kwargs to build url
            if to_urlencode != to_jsonify:
                if len(kwargs):
                    url += "?" + urlencode(kwargs)
            # set content-type as json by default
            headers["Content-type"] = "application/json"
            # if explicitly asked to send data as urlencoded
            if to_urlencode is not None:
                data = urlencode(to_urlencode)
                headers["Content-type"] = "application/x-www-form-urlencoded"
            # if explicitly asked to send data as json
            elif to_jsonify is not None:
                data = json.dumps(to_jsonify)
            # if nothing provided send void json as data
            else:
                data = json.dumps(kwargs)
            req = Request(url, data.encode('utf-8'), headers)

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


CONNECT = EndPoint(method=lambda *a, **kw: EndPoint._call("CONNECT", *a, **kw))
DELETE = EndPoint(method=lambda *a, **kw: EndPoint._call("DELETE", *a, **kw))
GET = EndPoint(method=lambda *a, **kw: EndPoint._call("GET", *a, **kw))
HEAD = EndPoint(method=lambda *a, **kw: EndPoint._call("HEAD", *a, **kw))
OPTIONS = EndPoint(method=lambda *a, **kw: EndPoint._call("OPTIONS", *a, **kw))
PATCH = EndPoint(method=lambda *a, **kw: EndPoint._call("PATCH", *a, **kw))
POST = EndPoint(method=lambda *a, **kw: EndPoint._call("POST", *a, **kw))
PUT = EndPoint(method=lambda *a, **kw: EndPoint._call("PUT", *a, **kw))
TRACE = EndPoint(method=lambda *a, **kw: EndPoint._call("TRACE", *a, **kw))
