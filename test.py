# test.py
from usrv import route


# allow req.Endpoint.connect
@route.bind("/", methods=["HEAD"])
def base():
    return 200,


# public key endoint for encryption
@route.bind("/puk", methods=["GET"])
def puk():
    return 200, route.PUBLIC_KEY


@route.bind("/index")
def index(*args):
    return (200, ) + args


@route.bind("/api/endpoint", methods=["GET", "POST"])
def endpoit(a, b, **kwargs):
    method = kwargs["method"]
    if method == "POST":
        return 202, kwargs["data"]
    elif method == "GET":
        return 200, a, b
    else:
        return 404,


route.run(host='127.0.0.1', port=5000)
