# -*- coding: utf-8 -*-
# © THOORENS Bruno

import io
import csv
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


def _trex_v3call(method="GET", *args, **kwargs):
    if TREX_KEY and TREX_SEC:
        r = req.EndPoint.build_req(method, *args, **kwargs)

        # https://bittrex.github.io/api/v3#topic-Authentication
        timestamp = int(time.time()*1000)
        content_hash = hashlib.sha512(
            b"" if r.data is None else r.data
        ).hexdigest()
        presign = "%d%s%s%s" % (
            timestamp, r.get_full_url(), method, content_hash
        )
        apisign = hmac.new(
            TREX_SEC if isinstance(TREX_SEC, bytes) else
            TREX_SEC.encode("utf-8"),
            presign if isinstance(presign, bytes) else
            presign.encode("utf-8"),
            hashlib.sha512
        ).hexdigest()

        r.add_header(
            "Api-Key",
            TREX_KEY.decode("latin-1") if isinstance(apisign, bytes) else
            TREX_KEY
        )
        r.add_header("Api-Timestamp", timestamp)
        r.add_header(
            "Api-Content-Hash",
            content_hash.decode("latin-1") if isinstance(apisign, bytes) else
            content_hash
        )
        r.add_header(
            "Api-Signature",
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


def bittrex_v3filter(**kwargs):
    kw = {"peer": "https://api.bittrex.com/v3"}
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


def use_v3_api():
    global GET, REQ

    GET = req.EndPoint(
        method=lambda *a, **kw:
            _trex_v3call("GET", *a, **bittrex_v3filter(**kw))
    )
    REQ = req.EndPoint(
        method=lambda *a, **kw:
            _trex_v3call("POST", *a, **bittrex_v3filter(**kw))
    )


def download_deposits(filename="deposits.csv"):
    data = [{"id": ""}]
    result = []
    while len(data) > 0 and isinstance(data, list):
        data = GET.deposits.closed(pageSize=200, nextPageToken=data[-1]["id"])
        result += data

    with io.open(filename, "w", newline='') as csvfile:
        writer = csv.DictWriter(
            csvfile, list(result[0].keys()),
            extrasaction="ignore", delimiter=";"
        )
        writer.writeheader()
        for row in result:
            writer.writerow(row)


def download_withdrawals(filename="withdrawals.csv"):
    data = [{"id": ""}]
    result = []
    while len(data) > 0 and isinstance(data, list):
        data = GET.withdrawals.closed(
            pageSize=200, nextPageToken=data[-1]["id"]
        )
        result += data

    with io.open(filename, "w", newline='') as csvfile:
        writer = csv.DictWriter(
            csvfile, list(result[0].keys()),
            extrasaction="ignore", delimiter=";"
        )
        writer.writeheader()
        for row in result:
            writer.writerow(row)
