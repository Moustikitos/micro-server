# -*- coding: utf-8 -*-
# © THOORENS Bruno

import typing

from usrv import req

PEER = "https://api.pinata.cloud"
HEADERS = {"Accept": "application/json"}


def link(token: str) -> None:
    """
    Set the authorization token for Pinata API requests.

    Args:
        token (str): The Bearer token for authorization.
    """
    HEADERS["Authorization"] = "Bearer %s" % token


def pinata_kwargs(kwargs: dict) -> dict:
    """
    Prepare additional arguments for Pinata API requests.

    Args:
        kwargs (dict): The original keyword arguments.

    Returns:
        dict: The updated arguments including peer, headers, and encoder.
    """
    kwargs["_peer"] = PEER
    kwargs["_headers"] = HEADERS
    kwargs["_encoder"] = req.json.dumps
    return kwargs


def pinFile(
    name: str, pathfile: str, options: dict = {}, **metadata
) -> typing.Any:
    """
    Pin a file to IPFS using the Pinata API.

    Args:
        name (str): The name of the pinned file.
        pathfile (str): The local path to the file to be pinned.
        options (dict, optional): Additional options for pinning, such as
            'cidVersion'. Defaults to an empty dictionary.
        **metadata: Key-value metadata pairs for the pinned file.

    Returns:
        typing.Any: The API response from Pinata.
    """
    metadata["name"] = name
    options["cidVersion"] = options.get("cidVersion", "1")
    return POST.pinning.pinFileToIPFS(
        _encoder=req.FormData.encode,
        file=pathfile, pinataOptions=options, pinataMetadata=metadata
    )


def updateMetadata(name: str, ipfs_hash: str, **metadata) -> typing.Any:
    """
    Update metadata for a pinned file on Pinata.

    Args:
        name (str): The name of the pinned file.
        ipfs_hash (str): The IPFS hash of the pinned file.
        **metadata: Key-value metadata pairs to update.

    Returns:
        typing.Any: The API response from Pinata.
    """
    return PUT.pinning.hashMetadata(
        name=name, ipfsPinHash=ipfs_hash, keyvalues=metadata
    )


# Pinata root endpoints
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
