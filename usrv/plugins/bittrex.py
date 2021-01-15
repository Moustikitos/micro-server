# -*- coding: utf-8 -*-
# © THOORENS Bruno

import time
import hmac
import hashlib

from usrv import req, loadJson


TREX_KEY = None
TREX_SEC = None


def link(key, sec):
    global TREX_KEY, TREX_SEC
    TREX_KEY = key
    TREX_SEC = sec


def unlink():
    global TREX_KEY, TREX_SEC
    TREX_KEY = None
    TREX_SEC = None


def open(name):
    global TREX_KEY, TREX_SEC
    data = loadJson(name + ".trex")
    if data != {}:
        TREX_KEY = data.get("key", None)
        TREX_SEC = data.get("secret", None)


close = unlink


def _trex_call(method="GET", *args, **kwargs):
    secret = kwargs.pop("secret", False)
    r = req.EndPoint.build_req(method, *args, **kwargs)

    if secret:
        apisign = hmac.new(
            secret if isinstance(secret, bytes) else secret.encode("utf-8"),
            r.get_full_url().encode("utf-8"),
            hashlib.sha512
        ).hexdigest()

        r.add_header(
            "apisign",
            apisign.decode("latin-1") if isinstance(apisign, bytes) else
            apisign
        )

    return req.EndPoint._open(r)


def bittrex_filter(**kwargs):
    kw = {"peer": "https://api.bittrex.com/api/v1.1"}
    if not (TREX_KEY is None and TREX_SEC is None):
        kw.update({
            "secret": kwargs.pop("secret", TREX_SEC),
            "apikey": kwargs.pop("apikey", TREX_KEY),
            "nonce": kwargs.pop("nonce", int(time.time()))
        })
    kw.update(kwargs)
    return kw


GET = req.EndPoint(
    method=lambda *a, **kw:
        _trex_call("GET", *a, **bittrex_filter(**kw))
)
POST = req.EndPoint(
    method=lambda *a, **kw:
        _trex_call("POST", *a, **bittrex_filter(**kw))
)
