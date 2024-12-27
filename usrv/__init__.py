# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
# Package Name: usrv

This package implements a lightweight Web Server Gateway Interface (WSGI)
for deploying Python web applications. It follows the WSGI specification
outlined in PEP 3333, providing a flexible interface for handling HTTP
requests and responses.

## Modules:
- wsgi: Implements the core WSGI functionality, including request
  handling and URL reconstruction.
- route: Provides the web server capabilities, handling of incoming requests
  and endpoint management.
- req: Provides a light request interface and with a pythonic way to access
  remote resources.
- app: Provides the root app to be run behind WSGI for production mode.

## Features:
- Route binding: Easily bind URL patterns to Python functions.
- Flexible response handling: Customize responses based on the request
  method and URL.
- Error management: Handle common HTTP errors with appropriate status codes.

## Usage:
To use this package, import the relevant modules and define your endpoints
using the provided routing functionality. Start the server with the desired
configuration for host, port, and threading options.

For more details, see the documentation and examples in the respective modules.
"""

import io
import os
import json
import logging

# set basic logging
logging.basicConfig()
LOG = logging.getLogger("usrv")
# configuration pathes
ROOT = os.path.abspath(os.path.dirname(__file__))
JSON = os.path.abspath(os.path.join(ROOT, ".json"))
__path__.append(os.path.abspath(os.path.join(ROOT, "plugins")))


def loadJson(name, folder=None):
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
    #
    return data


def dumpJson(data, name, folder=None):
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
    #
