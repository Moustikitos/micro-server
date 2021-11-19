# -*- coding: utf-8 -*-
# © THOORENS Bruno

import socket

from usrv import req

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def get_public_ip():
    result = req.GET.plain(peer="https://www.ipecho.net").get("raw", None)
    if result is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            result = s.getsockname()[0]
        except Exception:
            result = '127.0.0.1'
        finally:
            s.close()
    return result


def ipinfo_filter(**kwargs):
    return dict(kwargs, peer="https://ipinfo.io", headers=HEADERS)


def link(token):
    HEADERS["Authorization"] = "Bearer %s" % token


GET = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "GET", *a, **ipinfo_filter(**kw)
    )
)

POST = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "POST", *a, **ipinfo_filter(**kw)
    )
)

PUSH = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "PUSH", *a, **ipinfo_filter(**kw)
    )
)

DELETE = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "DELETE", *a, **ipinfo_filter(**kw)
    )
)


def info(ip, **kwargs):
    return GET(ip, **kwargs)


def localize():
    return info(get_public_ip())
