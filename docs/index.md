<a id="usrv"></a>

# usrv

__Package Name: usrv__


This package implements a lightweight Web Server Gateway Interface (WSGI)
for deploying Python web applications. It follows the WSGI specification
outlined in PEP 3333, providing a flexible interface for handling HTTP
requests and responses.

## Modules
- wsgi: Implements the core WSGI functionality, including request
  handling and URL reconstruction.
- route: Provides the web server capabilities, handling of incoming requests
  and endpoint management.
- req: Provides a light request interface and with a pythonic way to access
  remote resources.
- app: Provides the root app to be run behind WSGI for production mode.
- secp256k1: Provides all functions for ECIES encryption and ECDSA signature.

## Features
- Route binding: Easily bind URL patterns to Python functions.
- Flexible response handling: Customize responses based on the request
  method and URL.
- Error management: Handle common HTTP errors with appropriate status codes.
- Encryption: server and client side HTTP body encryption on demand.

## Usage
To use this package, import the relevant modules and define your endpoints
using the provided routing functionality. Start the server with the desired
configuration for host, port, and threading options.

`usrv` package also provides `FormData` class that implements
`multipart/form-data` body.

<a id="usrv.FormData"></a>

## FormData Objects

```python
class FormData(list)
```

Implementation of multipart/form-data encoder.

This class provides methods to construct, encode, and decode
multipart/form-data content, as described in [RFC 7578](https://datatracker.ietf.org/doc/html/rfc7578).

<a id="usrv.FormData.append_json"></a>

### FormData.append\_json

```python
def append_json(name: str, value: dict = {}, **kwval) -> None
```

Add a JSON object to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `value` _dict, optional_ - A dictionary representing the JSON object.
  Defaults to None.
- `kwval` - Additional key-value pairs to include in the JSON object.
  

**Returns**:

- `typing.Any` - The updated FormData instance.

<a id="usrv.FormData.append_value"></a>

### FormData.append\_value

```python
def append_value(name: str, value: typing.Union[str, bytes],
                 **headers) -> None
```

Add a text or binary value to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `value` _Union[str, bytes]_ - The value to add. Can be a string or
  bytes.
- `headers` - Additional headers to include for this field.

<a id="usrv.FormData.append_file"></a>

### FormData.append\_file

```python
def append_file(name: str, path: str) -> typing.Any
```

Add a file to the multipart body.

**Arguments**:

- `name` _str_ - The name of the form field.
- `path` _str_ - The path to the file to be added.
  

**Raises**:

- `IOError` - If the file does not exist.

<a id="usrv.FormData.dumps"></a>

### FormData.dumps

```python
def dumps() -> str
```

Encode the FormData instance as a multipart/form-data body.

**Returns**:

- `str` - The encoded body and the corresponding Content-Type header.

<a id="usrv.FormData.dump"></a>

### FormData.dump

```python
def dump(folder: str = None) -> None
```

Save the FormData instance to files in a directory.

Each field in the FormData is written to a separate file.
Additional metadata is saved as JSON.

**Returns**:

  None

<a id="usrv.FormData.encode"></a>

### FormData.encode

```python
@staticmethod
def encode(data: dict) -> str
```

Encode a dictionary as a multipart/form-data string.

**Arguments**:

- `data` _dict_ - The data to encode. Can include filepath, strings, or
  FormData instances.
  

**Returns**:

- `str` - The encoded multipart/form-data string.

<a id="usrv.FormData.decode"></a>

### FormData.decode

```python
@staticmethod
def decode(data: str) -> typing.Any
```

Decode a multipart/form-data string into a FormData instance.

**Arguments**:

- `data` _str_ - The multipart/form-data string to decode.
  

**Returns**:

- `FormData` - The decoded FormData instance.

