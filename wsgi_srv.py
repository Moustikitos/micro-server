# -*- coding: utf-8 -*-
# © THOORENS Bruno

"""
This module serves as an HTTP server using the Waitress WSGI server.

It provides command-line options for configuring the server's host, port, log
level, and number of threads. If no additional modules are specified as
arguments, default routes are defined for testing purposes, including endpoints
that demonstrate handling of positional and keyword arguments, as well as error
scenarios.

## Command-line options:
    --threads: Set the number of threads to use (default: 2).
    --log-level: Set the logging level from 1 to 100 (default: 20).
    --ip: Specify the IP address for the server (default: 127.0.0.1).
    --port: Specify the port for the server (default: 5000).

## Example usage:

```bash
$ python wsgi_py.py --threads 4 --log-level 30 --ip 0.0.0.0 --port 8000
```
"""

import os
import sys
import waitress
import importlib
import traceback

from optparse import OptionParser
from usrv import app, route, LOG

# Configure command-line argument parsing.
parser = OptionParser(
    usage="usage: %prog [options] BINDINGS...",
    version="%prog 1.0"
)
parser.add_option(
    "-t", "--threads", action="store", dest="threads", default=2,
    type="int",
    help="set thread number           [default: 2]"
)
parser.add_option(
    "-l", "--log-level", action="store", dest="loglevel", default=20,
    type="int",
    help="set log level from 1 to 100 [default: 20]"
)
parser.add_option(
    "-i", "--ip", action="store", dest="host", default="127.0.0.1",
    help="ip to run from              [default: 127.0.0.1]"
)
parser.add_option(
    "-p", "--port", action="store", dest="port", default=5000,
    type="int",
    help="port to use                 [default: 5000]"
)
(options, args) = parser.parse_args()

# Define default routes if no modules are specified in arguments.
if len(args) == 0:
    @route.bind("/")
    def test0() -> tuple:
        """Return a test page."""
        return 200, "Test page"

    @route.bind("/vargs")
    def test1(a, b=1, c=0, *args) -> tuple:
        """
        Demonstrate handling of positional arguments.

        Args:
            a: First argument.
            b: Second argument (default=1).
            c: Third argument (default=0).
            *args: Additional positional arguments.

        Returns:
            tuple: HTTP status code and the received arguments.
        """
        return 200, a, b, c, args

    @route.bind("/kwargs")
    def test2(name, a, b=2, **kwargs) -> tuple:
        """
        Demonstrate handling of keyword arguments.

        Args:
            name: Name parameter.
            a: Parameter a.
            b: Parameter b (default=2).
            **kwargs: Additional keyword arguments.

        Returns:
            tuple: HTTP status code and the received arguments.
        """
        return 200, name, a, b, kwargs

    @route.bind("/error_406")
    def test3(a, b=2, *args, **kwargs) -> tuple:
        """
        Example endpoint that returns a 406 error.

        Args:
            a: First parameter.
            b: Second parameter (default=2).
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            tuple: received arguments without HTTP status code.
        """
        return a, b, args, kwargs

    @route.bind("/error_500")
    def test4(a, b=2, *args, **kwargs) -> None:
        """
        Example endpoint that raises an exception.

        Args:
            a: First parameter.
            b: Second parameter (default=2).
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Raises:
            Exception: Simulates a server-side error.
        """
        raise Exception

else:
    # Extend system path from a specified path file if it exists.
    executable = os.path.splitext(os.path.basename(__file__))[0]
    if os.path.exists(f"{executable}.path"):
        with open(f"{executable}.path", "r") as pathes:
            sys.path.extend([
                os.path.normpath(path.strip())
                for path in pathes.read().split("\n")
            ])
    # Dynamically import modules specified in command line arguments.
    for name in args:
        try:
            importlib.import_module(name)
        except ModuleNotFoundError:
            LOG.error(
                f"module {name} not found in path:{'\n    '.join(sys.path)}"
            )
        except ImportError as error:
            LOG.error("%r\n%s", error, traceback.format_exc())

# Set log level and start the server.
LOG.setLevel(options.loglevel)
LOG.info("listening on %s:%s\nCTRL+C to stop...", options.host, options.port)
waitress.serve(
    app.uApp(), host=options.host, port=options.port, threads=options.threads
)
LOG.info("server stopped")
