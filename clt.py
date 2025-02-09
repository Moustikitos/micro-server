# -*- coding: utf-8 -*-
# © THOORENS Bruno

import sys

from usrv import req

try:
    from msvcrt import getch
except ImportError:
    def getch():
        """
        Gets a single character from STDIO.
        """
        import sys
        import tty
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

ROOT_CMD = ["HEAD", "GET", "POST", "PUT", "PUSH", "DELETE"]
SERVER_PUBLIC_KEY = None
CLIENT_PUBLIC_KEY = req.PUBLIC_KEY

req.LOG.setLevel(20)
try:
    req.Endpoint.connect(sys.argv[1])
except Exception:
    req.LOG.error(f"peer not available: {sys.argv[1:]}")
    print("Press any key to continue...")
    getch()
    sys.exit(1)
else:
    print(f"clt tool 0.4.2\nConnected to {sys.argv[1]}\nCTRL+C to stop...")
    try:
        SERVER_PUBLIC_KEY = req.GET.puk()
        print(f"Server public key: {SERVER_PUBLIC_KEY}")
    except Exception:
        print("No '/puk' endpoint found for server public key")
    print(f"Client public key: {req.PUBLIC_KEY}")


while True:
    try:
        cmd = (input("@<< ")).split(" ")
        if len(cmd) > 1 and cmd[0] in ROOT_CMD:
            args, kwargs = (), {}
            endpoint = getattr(req, cmd[0])
            for part in cmd[1].split("/"):
                endpoint = getattr(endpoint, part)
            for elem in cmd[2:]:
                if "=" in elem:
                    key, value = elem.split("=")
                    try:
                        value = eval(value, globals(), locals())
                    except Exception as error:
                        req.LOG.debug(f"{error}")
                    kwargs[key] = value
                else:
                    args += (elem,)
            print(">", endpoint(**kwargs))
        elif cmd[0] == "/eval":
            eval(" ".join(cmd[1:]), globals(), locals())
    except KeyboardInterrupt:
        break
    except Exception as error:
        req.LOG.error(f"{error}")
