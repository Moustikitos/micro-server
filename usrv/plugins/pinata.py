# -*- coding: utf-8 -*-
# © THOORENS Bruno

import typing

from usrv import req

PEER = "https://api.pinata.cloud"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def link(token: str) -> None:
    HEADERS["Authorization"] = "Bearer %s" % token


def pinata_kwargs(kwargs: dict) -> dict:
    kwargs["_peer"] = PEER
    kwargs["_headers"] = HEADERS
    return kwargs


GET = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("GET", url, **pinata_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)

POST = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("POST", url, **pinata_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)

PUT = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("PUT", url, **pinata_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)


DELETE = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("DELETE", url, **pinata_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)


def pinFile(pathfile: str, options: dict = {}, **metadata) -> typing.Any:
    options["cidVersion"] = options.get("cidVersion", "1")
    return POST.pinning.pinFileToIPFS(
        _encoder=req.FormData.encode,
        file=pathfile, pinataOptions=options, pinataMetadata=metadata
    )
