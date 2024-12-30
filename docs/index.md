<a id="usrv"></a>

# usrv

__Package Name: usrv__


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

