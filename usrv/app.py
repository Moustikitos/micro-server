# -*- coding: utf-8 -*-
# © THOORENS Bruno

import os
import ssl
import logging
import traceback

from usrv import route, wsgi, LOG
from http.server import HTTPServer


class uApp:

    def __init__(
        self, host="127.0.0.1", port=5000, loglevel=30,
        handler=route.uHTTPRequestHandler
    ):
        self.loglevel = loglevel
        self.handler = handler
        self.host = host
        self.port = port

    def __call__(self, environ, start_response):
        return wsgi.wsgi_call(self.handler, environ, start_response)

    def wrap(self):
        if not hasattr(self, "httpd"):
            LOG.error("ssl wrap done only if server runs from python lib")
            return False
        path = os.path.dirname(os.path.abspath(__file__))
        try:
            if not os.path.exists("%s/cert.pem" % path):
                os.system(
                    "openssl req -x509 -newkey rsa:2048 "
                    "-keyout %(path)s/key.pem -out %(path)s/cert.pem -days 365"
                    % {"path": path}
                )
        except Exception as error:
            LOG.error("%r\n%s", error, traceback.format_exc())
            return False
        else:
            if os.path.exists("%s/cert.pem" % path):
                self.httpd.socket = ssl.wrap_socket(
                    self.httpd.socket,
                    keyfile="%s/key.pem" % path,
                    certfile="%s/cert.pem" % path,
                    server_side=True
                )
                return True
        return False

    def run(self, ssl=False):
        """
        For testing purpose only.
        """
        self.httpd = HTTPServer((self.host, self.port), self.handler)
        LOG.setLevel(self.loglevel)
        print(LOG.level)
        if ssl:
            self.wrap()
            LOG.info("ssl socket wrapping done")
        try:
            LOG.info(
                "listening on %s:%s\nCTRL+C to stop...",
                self.host, self.port
            )
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            LOG.info("server stopped")


if __name__ == "__main__":
    app = uApp()
    app.run()
