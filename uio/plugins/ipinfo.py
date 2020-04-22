# -*- coding: utf-8 -*-
# © THOORENS Bruno

import socket

from uio import req

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


def link(token):
    HEADERS["Authorization"] = "Bearer %s" % token


def info(ip, **kwargs):
    return req.GET(ip, peer="http://ipinfo.io", **kwargs)


def localize():
    return req.GET(get_public_ip(), peer="http://ipinfo.io", headers=HEADERS)
