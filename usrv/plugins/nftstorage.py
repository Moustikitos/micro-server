# -*- coding: utf-8 -*-
# © THOORENS Bruno

import os

from usrv import req
from collections.abc import Mapping


HEADERS = {
    "Content-Type": "application/json",
    "User-agent": "Mozilla/5.0",
    "Accept": "application/json",
}


def nftstorage_filter(**kwargs):
    return dict(kwargs, peer="https://api.nft.storage", headers=HEADERS)


def link(token):
    HEADERS["Authorization"] = "Bearer %s" % token


GET = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "GET", *a, **nftstorage_filter(**kw)
    )
)

POST = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "POST", *a, **nftstorage_filter(**kw)
    )
)

PUSH = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "PUSH", *a, **nftstorage_filter(**kw)
    )
)

DELETE = req.EndPoint(
    method=lambda *a, **kw: req.EndPoint._call(
        "DELETE", *a, **nftstorage_filter(**kw)
    )
)


def _ERC1155_filter(data, root=None):
    result = {}
    for key, value in list(data.items()):
        root_ = key if root is None else "%s.%s" % (root, key)
        if isinstance(value, Mapping):
            result.update(_ERC1155_filter(value, root_))
        elif isinstance(value, str):
            abspath = os.path.abspath(value)
            if os.path.isfile(abspath):
                data[key] = None
                result[root_] = abspath
    return result


def upload(*pathfiles):
    data = req.FormData()
    for pathfile in pathfiles:
        data.append_file("file", pathfile)
    return POST.upload(_multipart=data)


def store_ERC1155(schema):
    data = req.FormData()
    filtered = _ERC1155_filter(schema)
    data.append_json("meta", schema)
    for key, filepath in filtered.items():
        data.append_file(key, filepath)
    return POST.store(_multipart=data)
