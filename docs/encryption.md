<a id="usrv.secp256k1"></a>

# secp256k1

<a id="usrv.secp256k1.EncryptionError"></a>

## EncryptionError Objects

```python
class EncryptionError(Exception)
```

Custom exception for encryption errors.

<a id="usrv.secp256k1.bip39_hash"></a>

## bip39\_hash

```python
def bip39_hash(secret: str, passphrase: str = "SALT") -> bytes
```

Returns bip39 hash bytes string. This function does not check mnemonic
integrity.

**Arguments**:

- `secret` _str_ - a mnemonic string.
- `passphrase` _str_ - salt string.
  

**Returns**:

- `bytes` - 64 length bytes string.

<a id="usrv.secp256k1.y_from_x"></a>

## y\_from\_x

```python
def y_from_x(x: int) -> int
```

Computes y from x according to `secp256k1` equation.

<a id="usrv.secp256k1.encode"></a>

## encode

```python
def encode(point: tuple) -> str
```

Compresses `secp256k1` point or signature.

**Arguments**:

- `tuple` - Point on `secp256k1` curve or `secp256k1` signature.
  

**Returns**:

- `pubkey` _str_ - Compressed and encoded point.

<a id="usrv.secp256k1.decode"></a>

## decode

```python
def decode(puk: str) -> tuple
```

Decompresses a compressed `secp256k1` point.

**Arguments**:

- `pubkey` _str_ - Compressed and encoded point.
  

**Returns**:

- `tuple` - Point on `secp256k1` the curve.

<a id="usrv.secp256k1.b64encode"></a>

## b64encode

```python
def b64encode(point: tuple) -> str
```

Encodes an elliptic curve point or ECDSA signatures as a base64 string.

**Arguments**:

- `point` _tuple_ - The elliptic curve point as a tuple (x, y), where x and
  y are integers.
  

**Returns**:

- `str` - The base64-encoded string representing the point.

<a id="usrv.secp256k1.b64decode"></a>

## b64decode

```python
def b64decode(raw: str) -> tuple
```

Decodes a base64-encoded string into an elliptic curve point or ECDSA
signature.

**Arguments**:

- `raw` _str_ - The base64-encoded string.
  

**Returns**:

- `tuple` - The elliptic curve point as a tuple (x, y).

<a id="usrv.secp256k1.mod_inverse"></a>

## mod\_inverse

```python
def mod_inverse(k: int, p: int) -> int
```

Computes the modular inverse using the extended Euclidean algorithm.

**Arguments**:

- `k` _int_ - The integer to invert.
- `p` _int_ - The modulus.
  

**Returns**:

- `int` - The modular inverse of k modulo p.
  

**Raises**:

- `ZeroDivisionError` - If k is zero.

<a id="usrv.secp256k1.point_add"></a>

## point\_add

```python
def point_add(C: tuple, D: tuple) -> tuple
```

Adds two points on the elliptic curve.

**Arguments**:

- `C` _tuple_ - The first point as a tuple (x, y).
- `D` _tuple_ - The second point as a tuple (x, y).
  

**Returns**:

- `tuple` - The resulting point after addition.

<a id="usrv.secp256k1.point_double"></a>

## point\_double

```python
def point_double(C: tuple) -> tuple
```

Doubles a point on the elliptic curve.

**Arguments**:

- `C` _tuple_ - The point to double as a tuple (x, y).
  

**Returns**:

- `tuple` - The resulting point after doubling.

<a id="usrv.secp256k1.point_multiply"></a>

## point\_multiply

```python
def point_multiply(k: int, C: tuple) -> tuple
```

Multiplies a point P by a scalar k on the elliptic curve.

**Arguments**:

- `k` _int_ - The scalar multiplier.
- `C` _tuple_ - The point to multiply as a tuple (x, y).
  

**Returns**:

- `tuple` - The resulting point after multiplication.

<a id="usrv.secp256k1.generate_keypair"></a>

## generate\_keypair

```python
def generate_keypair(secret: str = None)
```

Generates a private and public key pair for SECP256k1.

**Returns**:

- `tuple` - A tuple containing the private key (int) and the base64-encoded
  public key.

<a id="usrv.secp256k1.sign"></a>

## sign

```python
def sign(message: str, private_key: int) -> str
```

Generates an ECDSA message signature using a private key.

**Arguments**:

- `message` _str_ - The message to sign.
- `private_key` _int_ - The private key used for signing.
  

**Returns**:

- `str` - The base64-encoded signature.

<a id="usrv.secp256k1.verify"></a>

## verify

```python
def verify(message: str, signature: str, public_key: str) -> bool
```

Verifies an ECDSA signature using a public key.

**Arguments**:

- `message` _str_ - The signed message.
- `signature` _str_ - The base64-encoded signature.
- `public_key` _str_ - The base64-encoded public key.
  

**Returns**:

- `bool` - True if the signature is valid, False otherwise.

<a id="usrv.secp256k1.aes_encrypt"></a>

## aes\_encrypt

```python
def aes_encrypt(data: str, secret: str) -> str
```

Encrypts data using AES with a secret.

**Arguments**:

- `data` _str_ - The plaintext data to encrypt.
- `secret` _str_ - The secret key for encryption.
  

**Returns**:

- `str` - The encrypted data as a hexadecimal string.

<a id="usrv.secp256k1.aes_decrypt"></a>

## aes\_decrypt

```python
def aes_decrypt(data: str, secret: str) -> str
```

Decrypts AES-encrypted data using a secret.

**Arguments**:

- `data` _str_ - The encrypted data as a hexadecimal string.
- `secret` _str_ - The secret key for decryption.
  

**Returns**:

- `str|bool` - The decrypted plaintext data, or False if
  decryption fails.

<a id="usrv.secp256k1.encrypt"></a>

## encrypt

```python
def encrypt(public_key: str, message: str) -> typing.Tuple[str, str]
```

Encrypts a message using a public key.

**Arguments**:

- `public_key` _str_ - The base64-encoded public key.
- `message` _str_ - The plaintext message to encrypt.
  

**Returns**:

- `tuple` - A tuple containing the base64-encoded R value and the encrypted
  message as a hexadecimal string.

<a id="usrv.secp256k1.decrypt"></a>

## decrypt

```python
def decrypt(private_key: int, R: str, ciphered: str) -> str
```

Decrypts a message using a private key.

**Arguments**:

- `private_key` _int_ - The base64-encoded private key.
- `R` _str_ - The base64-encoded ephemeral public key.
- `ciphered` _str_ - The ciphered message to decrypt.
  

**Returns**:

- `str` - Message as plaintext.

<a id="usrv.secp256k1.dump_secret"></a>

## dump\_secret

```python
def dump_secret(secret: str = None) -> None
```

Securely stores a secret using a PIN.

The secret is encrypted with AES using a key derived from a PIN.
The encrypted file is saved in a specified directory.

**Arguments**:

- `secret` _str_ - The secret to be encrypted and stored.

<a id="usrv.secp256k1.load_secret"></a>

## load\_secret

```python
def load_secret() -> typing.Optional[str]
```

Loads and decrypts a secret using a PIN.

The file containing the secret is identified by a SHA256 hash of the PIN.
If the file exists, its contents are decrypted and returned.

**Returns**:

- `Optional[str]` - The decrypted secret, or None if the file does not
  exist.

