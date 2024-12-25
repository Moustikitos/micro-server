# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module contains all the utilities to launch a WSGI micro server (highly
recommended in production mode).
"""

import os
import ssl
import traceback

from usrv import route, wsgi, LOG
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections.abc import Callable


class uApp:
    """
    Represents a lightweight application server that can handle HTTP requests,
    optionally wrap its socket with SSL, and run in a testing mode.

    Attributes:
        handler (BaseHTTPRequestHandler): HTTP request handler.
        host (str): The hostname for the server.
        port (int): The port number for the server.
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 5000, loglevel: int = 20,
        handler: BaseHTTPRequestHandler = route.uHTTPRequestHandler
    ):
        """
        Initializes the uApp instance with a specified host, port, logging
        level, and request handler.

        Args:
            host (str): Hostname for the server. Defaults to "127.0.0.1".
            port (int): Port number for the server. Defaults to 5000.
            loglevel (int): Logging level. Defaults to 20 (INFO).
            handler (BaseHTTPRequestHandler): Request handler.
                Defaults to `route.uHTTPRequestHandler`.
        """
        LOG.setLevel(loglevel)
        self.handler = handler
        self.host = host
        self.port = port

    def __call__(self, environ: dict, start_response: Callable) -> bytes:
        """
        Enables the application to be callable as a WSGI application.

        Args:
            environ (dict): The WSGI environment dictionary.
            start_response (callable): A callable to start the HTTP response.

        Returns:
            Callable: The response iterable.
        """
        return wsgi.wsgi_call(self.handler, environ, start_response)

    def wrap(self) -> bool:
        """
        Wraps the HTTP server's socket with SSL if a certificate and key are
        available.

        Returns:
            bool: True if the socket is successfully wrapped with SSL, False
                  otherwise.
        """
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

    def run(self, ssl: bool = False):
        """
        Starts the HTTP server, optionally wrapping the socket with SSL.
        This method is designed for testing purposes only.

        Args:
            ssl (bool): If True, wraps the server's socket with SSL. Defaults
                        to False.
        """
        self.httpd = HTTPServer((self.host, self.port), self.handler)
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
    app = uApp().run()
