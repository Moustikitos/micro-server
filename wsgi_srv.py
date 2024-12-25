# -*- coding: utf-8 -*-
# © THOORENS Bruno

import sys
import waitress
import importlib
import traceback

from optparse import OptionParser
from usrv import app, route, LOG

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

if len(args) == 0:
    # url, headers, data and method loosed
    @route.bind("/")
    def test0():
        return 200, "Test page"
    # get url, headers, data and method in args

    @route.bind("/vargs")
    def test1(a, b=1, c=0, *args):
        return 200, a, b, c, args
    # get url, headers, data and method in kwargs

    @route.bind("/kwargs")
    def test2(name, a, b=2, **kwargs):
        return 200, name, a, b, kwargs
    # get url, headers, data and method in kwargs

    @route.bind("/error_406")
    def test3(a, b=2, *args, **kwargs):
        return a, b, args, kwargs

    @route.bind("/error_500")
    def test4(a, b=2, *args, **kwargs):
        raise Exception

else:
    for name in args:
        try:
            importlib.import_module(name)
        except ModuleNotFoundError:
            LOG.error(
                f"module {name} not found in path:\n{'\n    '.join(sys.path)}"
            )
        except ImportError as error:
            LOG.error("%r\n%s", error, traceback.format_exc())

LOG.setLevel(options.loglevel)
LOG.info("listening on %s:%s\nCTRL+C to stop...", options.host, options.port)
waitress.serve(
    app.uApp(), host=options.host, port=options.port, threads=options.threads
)
LOG.info("server stopped")
