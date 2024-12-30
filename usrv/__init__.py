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
- secp256k1: Provides all functions for ECIES encryption and ECDSA signature.

## Features:
- Route binding: Easily bind URL patterns to Python functions.
- Flexible response handling: Customize responses based on the request
  method and URL.
- Error management: Handle common HTTP errors with appropriate status codes.
- Encryption: server and client side HTTP body encryption on demand.

## Usage:
To use this package, import the relevant modules and define your endpoints
using the provided routing functionality. Start the server with the desired
configuration for host, port, and threading options.

For more details, see the documentation and examples in the respective modules.
"""

import io
import os
import re
import json
import typing
import logging
import binascii
import mimetypes

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


class FormData(list):
    """
    ~ [RFC#7578](https://datatracker.ietf.org/doc/html/rfc7578)
    Implementation of multipart/form-data encoder.
    """

    def append_json(self, name: str, value: dict = {}, **kwval) -> typing.Any:
        list.append(self, {
            "name": name,
            "data": json.dumps(
                dict(value, **kwval), sort_keys=True, separators=(",", ":")
            ).encode("latin-1"),
            "headers": {"Content-Type": "application/json"}
        })
        return self

    def append_value(
        self, name: str, value: typing.Union[str, bytes], **headers
    ) -> typing.Any:
        list.append(self, {
            "name": name,
            "data": value if isinstance(value, bytes) else (
                "%s" % value
            ).encode("latin-1"),
            "headers": dict({"Content-Type": "text/plain"}, **headers)
        })
        return self

    def append_file(self, name: str, path: str) -> typing.Any:
        if os.path.isfile(path):
            list.append(self, {
                "name": name,
                "filename": os.path.basename(path),
                "headers": {
                    "Content-Type": (
                        mimetypes.guess_type(path)[0] or
                        "application/octet-stream"
                    )
                },
                "data": open(path, "rb").read()
            })
        else:
            raise IOError("file %s not found" % path)
        return self

    def dumps(self) -> str:
        body = b""
        boundary = binascii.hexlify(os.urandom(16))

        for value in [dict(v) for v in self]:
            field = value.pop("name").encode("latin-1")
            data = value.pop("data")
            headers = value.pop("headers")

            body += b'--' + boundary + b'\r\n'
            body += b'Content-Disposition: form-data; name="%s"; ' % field
            body += '; '.join(
                ['%s="%s"' % (n, v) for n, v in value.items()]
            ).encode("latin-1") + b'\r\n'
            body += (
                '\r\n'.join(
                    ['%s: %s' % (n, v) for n, v in headers.items()]
                ).encode("latin-1") + b"\r\n"
            ) or b'\r\n'
            body += b'\r\n' + data + b'\r\n'

        body += b'--' + boundary + b'--'
        return body, \
            f"multipart/form-data; boundary={boundary.decode("latin-1")}"

    def dump(self) -> None:
        boundary = binascii.hexlify(os.urandom(16)).decode("utf-8")
        root_folder = os.path.join(DATA, boundary)
        os.makedirs(root_folder, exist_ok=True)
        for elem in self:
            content_type = elem["headers"].get(
                "Content-Type", "application/octet-stream"
            )
            filename = elem.get("name", "undefined")
            ext = mimetypes.guess_extension(content_type) \
                or f".{content_type.replace('/', '.')}"
            with open(
                os.path.join(root_folder, f"{filename}{ext}"), "wb"
            ) as out:
                out.write(elem.get("data", b""))
            dumpJson(
                dict(
                    [k, v] for k, v in elem.items()
                    if k not in ["data", "name"]
                ), f"{filename}.values", root_folder
            )

    @staticmethod
    def encode(data: dict) -> str:
        result = FormData()
        for name, value in data.items():
            if isinstance(value, FormData):
                result.extend(value)
            elif os.path.isfile(value):
                result.append_file(name, value)
            else:
                result.append_value(name, value)
        return result.dumps()[0].decode("latin-1")

    @staticmethod
    def decode(data: str) -> typing.Any:
        result = FormData()
        boundary = re.match(".*(--[0-9a-f]+).*", data).groups()[0]

        frames = []
        # define frames by scanning lines
        for line in data.split("\r\n")[:-1]:
            if line == boundary:
                frames.append("")
            else:
                frames[-1] += line + "\r\n"

        for frame in frames:
            # separate lines to find void one (separator between info and data)
            splited = frame.split("\r\n")
            separator_index = splited.index("")
            # rebuild info and data
            info = "\r\n".join(splited[:separator_index])
            data = "\r\n".join(splited[separator_index+1:])
            # get all values from info
            values = dict(
                elem.replace('"', '').split("=")
                for elem in re.findall(r'([\w-]*[\s]*=[\s]*"[\S]*")', info)
            )
            # get headers from info
            headers = dict(
                elem.strip().replace(" ", "").split(":")
                for elem in re.findall(r'([\w-]*[\s]*:[\s]*[\S]*)', info)
            )
            # append item
            result.append(
                dict(
                    name=values.pop("name", "undefined"),
                    data=data.encode("latin-1"), headers=headers, **values
                )
            )

        return result
