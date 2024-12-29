<a id="wsgi_srv"></a>

# wsgi\_srv

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

