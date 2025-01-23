# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
# Package Name: usrv

This package implements a lightweight Web Server Gateway Interface (WSGI)
for deploying Python web applications. It follows the WSGI specification
outlined in PEP 3333, providing a flexible interface for handling HTTP
requests and responses.

## Modules
- wsgi: Implements the core WSGI functionality, including request
  handling and URL reconstruction.
- route: Provides the web server capabilities, handling of incoming requests
  and endpoint management.
- req: Provides a light request interface and with a pythonic way to access
  remote resources.
- app: Provides the root app to be run behind WSGI for production mode.
- secp256k1: Provides all functions for ECIES encryption and ECDSA signature.

## Features
- Route binding: Easily bind URL patterns to Python functions.
- Flexible response handling: Customize responses based on the request
  method and URL.
- Error management: Handle common HTTP errors with appropriate status codes.
- Encryption: server and client side HTTP body encryption on demand.

## Usage
To use this package, import the relevant modules and define your endpoints
using the provided routing functionality. Start the server with the desired
configuration for host, port, and threading options.
"""

import io
import os
import json
import time
import typing
import logging
import threading

from datetime import datetime, timezone, timedelta

# set basic logging
logging.basicConfig()
LOG = logging.getLogger("usrv")
# configuration pathes
ROOT = os.path.abspath(os.path.dirname(__file__))
DATA = os.path.abspath(os.path.join(ROOT, ".data"))
JSON = os.path.abspath(os.path.join(ROOT, ".json"))
__path__.append(os.path.abspath(os.path.join(ROOT, "plugins")))


def loadJson(name: str, folder: str = None) -> typing.Any:
    filename = os.path.join(JSON if not folder else folder, name)
    if os.path.exists(filename):
        with io.open(filename, "r", encoding="utf-8") as in_:
            data = json.load(in_)
    else:
        data = {}
    # hack to avoid "OSError: [Errno 24] Too many open files"
    # with pypy
    try:
        in_.close()
        del in_
    except Exception:
        pass
    return data


def dumpJson(data: typing.Any, name: str, folder: str = None) -> None:
    filename = os.path.join(JSON if not folder else folder, name)
    try:
        os.makedirs(os.path.dirname(filename))
    except OSError:
        pass
    with io.open(filename, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=4)
    # hack to avoid "OSError: [Errno 24] Too many open files"
    # with pypy
    try:
        out.close()
        del out
    except Exception:
        pass


class NonceManager:
    def __init__(self, delay=10):
        self.nonces = {}
        self.delay = timedelta(seconds=delay)
        self.lock = threading.Lock()

    def create_nonce(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def push_nonce(self, nonce, identity):
        try:
            delta = datetime.now(timezone.utc) - datetime.fromisoformat(nonce)
            if delta > self.delay:
                return False
        except ValueError:
            return False

        with self.lock:
            if identity in self.nonces.get(nonce, []):
                return False
            self.nonces[nonce] = self.nonces.get(nonce, []) + [identity]
        return True

    def check_nonce(self, nonce: str, identity: str) -> bool:
        if not nonce:
            return True
        elif self.push_nonce(nonce, identity):
            return True
        return False

    def flush_nonce(self):
        now = datetime.now(timezone.utc)
        expired = [
            nonce for nonce, identities in self.nonces.items()
            if now - datetime.fromisoformat(nonce) > self.delay
        ]
        with self.lock:
            for nonce in expired:
                self.nonces.pop(nonce)

    def start_flusher(self):
        def flusher():
            while True:
                time.sleep(2 * self.delay.total_seconds())
                self.flush_nonce()
        thread = threading.Thread(target=flusher, daemon=True)
        thread.start()


NONCES = NonceManager()
