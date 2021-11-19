# -*- coding: utf-8 -*-
# © THOORENS Bruno

from usrv import req

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def pinata_filter(**kwargs):
    return dict(kwargs, peer="https://api.pinata.cloud", headers=HEADERS)


def link(token):
    HEADERS["Authorization"] = "Bearer %s" % token


GET = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "GET", *a, **pinata_filter(**kw)
    )
)

POST = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "POST", *a, **pinata_filter(**kw)
    )
)

PUSH = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "PUSH", *a, **pinata_filter(**kw)
    )
)

DELETE = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "DELETE", *a, **pinata_filter(**kw)
    )
)
