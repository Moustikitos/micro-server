# -*- coding: utf-8 -*-
# © THOORENS Bruno

import io
import os
import sys
import json
import logging

# save python familly
PY3 = True if sys.version_info[0] >= 3 else False
if PY3:
    input = input
else:
    input = raw_input

# set basic logging
logging.basicConfig()
# configuration pathes
ROOT = os.path.abspath(os.path.dirname(__file__))
JSON = os.path.abspath(os.path.join(ROOT, ".json"))

__path__.append(os.path.abspath(os.path.join(ROOT, "plugins")))


def loadJson(name, folder=None, reload=False):
    filename = os.path.join(JSON if not folder else folder, name)
    if os.path.exists(filename):
        with io.open(filename) as in_:
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
    with io.open(filename, "w" if PY3 else "wb") as out:
        json.dump(data, out, indent=4)
    # hack to avoid "OSError: [Errno 24] Too many open files"
    # with pypy
    try:
        out.close()
        del out
    except Exception:
        pass
    #
