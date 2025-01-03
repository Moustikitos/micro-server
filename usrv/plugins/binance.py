# -*- coding: utf-8 -*-
# © THOORENS Bruno


import hmac
import hashlib

from usrv import req, secp256k1

PEER = "https://api.binance.com"
SECRET = ""
HEADERS = {}


def dump_secret(secret: str):
    """
    Stores a secret securely.

    Args:
        secret (str): The secret key to store.
    """
    secp256k1.dump_secret(secret)


def get_secret():
    """Loads the secret key into the global variable."""
    global SECRET
    if SECRET == "":
        SECRET = secp256k1.load_secret()


def get_server_time() -> int:
    """
    Fetches the server's current time.

    Returns:
        int: The server's current timestamp in milliseconds.
    """
    return req.GET.api.v3.time(_peer=PEER)['serverTime']


def link(api_key: str):
    """
    Links the client to the Binance API using an API key.

    Args:
        api_key (str): The Binance API key.
    """
    HEADERS['X-MBX-APIKEY'] = api_key
    get_secret()


def binance_kwargs(kwargs: dict) -> dict:
    """
    Prepares request parameters for Binance API.

    Args:
        kwargs (dict): The initial request parameters.

    Returns:
        dict: The request parameters with Binance-specific settings.
    """
    kwargs["_peer"] = PEER
    kwargs["_encoder"] = req.json.dumps
    return kwargs


def signed_kwargs(kwargs: dict) -> dict:
    """
    Prepares and signs request parameters for Binance API.

    Args:
        kwargs (dict): The initial request parameters.

    Returns:
        dict: The request parameters with a signature and Binance-specific
            settings.
    """
    kwargs["timestamp"] = get_server_time()
    kwargs["_peer"] = PEER
    kwargs["_headers"] = HEADERS
    kwargs["_encoder"] = req.json.dumps
    query_string = req.urlencode(
        [(k, v) for k, v in kwargs.items() if not k.startswith("_")]
    )
    kwargs["signature"] = hmac.new(
        SECRET.encode(), query_string.encode(), hashlib.sha256
    ).hexdigest()
    return kwargs


# secured POST HTTP request using user signature
SPOST = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("POST", url, **signed_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)


# secured GET HTTP request using user signature
SGET = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("GET", url, **signed_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)


GET = req.Endpoint(
    method=lambda url, **parameters: req.manage_response(
        req.OPENER.open(
            req.build_request("GET", url, **binance_kwargs(parameters)),
            timeout=req.Endpoint.timeout
        )
    )
)
