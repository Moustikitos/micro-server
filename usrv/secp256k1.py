# -*- coding: utf-8 -*-
# © THOORENS Bruno

import os
import re
import pyaes
import typing
import base64
import secrets
import hashlib
import getpass
import unicodedata

from binascii import hexlify, unhexlify

KEYS = os.path.abspath(os.path.join(os.path.dirname(__file__), ".keys"))

# Elliptic Curve SECP256k1 Parameters ---------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
# ---------------------------------------------------------------------


class EncryptionError(Exception):
    """Custom exception for encryption errors."""
    pass


def bip39_hash(secret: str, passphrase: str = "SALT") -> bytes:
    """
    Returns bip39 hash bytes string. This function does not check mnemonic
    integrity.

    Args:
        secret (str): a mnemonic string.
        passphrase (str): salt string.

    Returns:
        bytes: 64 length bytes string.
    """
    return hashlib.pbkdf2_hmac(
        "sha512", unicodedata.normalize("NFKD", secret).encode("utf-8"),
        unicodedata.normalize("NFKD", f"mnemonic{passphrase}").encode("utf-8"),
        iterations=2048, dklen=64
    )


def y_from_x(x: int) -> int:
    """
    Computes y from x according to `secp256k1` equation.
    """
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return y


def encode(point: tuple) -> str:
    """
    Compresses `secp256k1` point.

    Arguments:
        tuple: Point on `secp256k1` curve.

    Returns:
        pubkey (str): Compressed and encoded point.
    """
    x, y = point
    return f"{'02' if y % 2 == 0 else '03'}{x:064x}"


def decode(puk: str) -> tuple:
    """
    Decompresses a compressed `secp256k1` point.

    Arguments:
        pubkey (str): Compressed and encoded point.

    Returns:
        tuple: Point on `secp256k1` the curve.
    """
    x = int(puk[2:], 16)
    y = y_from_x(x)
    if y is None:
        raise ValueError("Point not on `secp256k1` curve")
    elif y % 2 != int(puk[0:2], 16) - 2:
        y = -y % P
    return x, y


def b64encode(point: tuple) -> str:
    """
    Encodes an elliptic curve point or ECDSA signatures as a base64 string.

    Args:
        point (tuple): The elliptic curve point as a tuple (x, y), where x and
            y are integers.

    Returns:
        str: The base64-encoded string representing the point.
    """
    a, b = point
    return base64.b64encode(unhexlify(f"{a:064x}{b:064x}")).decode("utf-8")


def b64decode(raw: str) -> tuple:
    """
    Decodes a base64-encoded string into an elliptic curve point or ECDSA
    signature.

    Args:
        raw (str): The base64-encoded string.

    Returns:
        tuple: The elliptic curve point as a tuple (x, y).
    """
    ab = hexlify(base64.b64decode(raw.encode("utf-8"))).decode()
    return int(ab[:64], 16), int(ab[64:], 16)


def mod_inverse(k: int, p: int) -> int:
    """
    Computes the modular inverse using the extended Euclidean algorithm.

    Args:
        k (int): The integer to invert.
        p (int): The modulus.

    Returns:
        int: The modular inverse of k modulo p.

    Raises:
        ZeroDivisionError: If k is zero.
    """
    if k == 0:
        raise ZeroDivisionError("Division by zero.")
    return pow(k, -1, p)


def point_add(C: tuple, D: tuple) -> tuple:
    """
    Adds two points on the elliptic curve.

    Args:
        C (tuple): The first point as a tuple (x, y).
        D (tuple): The second point as a tuple (x, y).

    Returns:
        tuple: The resulting point after addition.
    """
    if C == D:
        return point_double(A)
    elif C is None:
        return D
    elif D is None:
        return C

    x1, y1 = C
    x2, y2 = D

    if x1 == x2 and y1 != y2:
        return None

    s = ((y2 - y1) * mod_inverse(x2 - x1, P)) % P
    x3 = (s**2 - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(C: tuple) -> tuple:
    """
    Doubles a point on the elliptic curve.

    Args:
        C (tuple): The point to double as a tuple (x, y).

    Returns:
        tuple: The resulting point after doubling.
    """
    if C is None:
        return None

    x, y = C

    s = ((3 * x**2 + A) * mod_inverse(2 * y, P)) % P
    x3 = (s**2 - 2 * x) % P
    y3 = (s * (x - x3) - y) % P
    return (x3, y3)


def point_multiply(k: int, C: tuple) -> tuple:
    """
    Multiplies a point P by a scalar k on the elliptic curve.

    Args:
        k (int): The scalar multiplier.
        C (tuple): The point to multiply as a tuple (x, y).

    Returns:
        tuple: The resulting point after multiplication.
    """
    D = None
    while k:
        if k & 1:
            D = point_add(D, C)
        C = point_double(C)
        k >>= 1
    return D


# Génération de clé privée et publique
def generate_keypair(secret: str = None):
    """
    Generates a private and public key pair for SECP256k1.

    Returns:
        tuple: A tuple containing the private key (int) and the base64-encoded
            public key.
    """
    if secret is not None:
        private_key = int.from_bytes(bip39_hash(secret)) % N
    else:
        private_key = secrets.randbelow(N)
    public_key = point_multiply(private_key, G)
    return private_key, b64encode(public_key)


# Signature numérique (ECDSA)
def sign(message: str, private_key: int) -> str:
    """
    Generates an ECDSA message signature using a private key.

    Args:
        message (str): The message to sign.
        private_key (int): The private key used for signing.

    Returns:
        str: The base64-encoded signature.
    """
    z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    r, s = 0, 0
    while r == 0 or s == 0:
        k = secrets.randbelow(N)
        x, _ = point_multiply(k, G)
        r = x % N
        s = ((z + r * private_key) * mod_inverse(k, N)) % N
    return b64encode((r, s))


# Vérification de signature
def verify(message: str, signature: str, public_key: str) -> bool:
    """
    Verifies an ECDSA signature using a public key.

    Args:
        message (str): The signed message.
        signature (str): The base64-encoded signature.
        public_key (str): The base64-encoded public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    public_key = b64decode(public_key)
    r, s = b64decode(signature)
    if not (1 <= r < N and 1 <= s < N):
        return False

    z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    w = mod_inverse(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    x, y = point_add(point_multiply(u1, G), point_multiply(u2, public_key))
    return x % N == r


def aes_encrypt(data: str, secret: str) -> str:
    """
    Encrypts data using AES with a secret.

    Args:
        data (str): The plaintext data to encrypt.
        secret (str): The secret key for encryption.

    Returns:
        str: The encrypted data as a hexadecimal string.
    """
    h = hashlib.sha256(secret.encode("utf-8")).digest()
    aes = pyaes.AESModeOfOperationCTR(h)
    return hexlify(aes.encrypt(data.encode("utf-8"))).decode("utf-8")


def aes_decrypt(data: str, secret: str) -> str:
    """
    Decrypts AES-encrypted data using a secret.

    Args:
        data (str): The encrypted data as a hexadecimal string.
        secret (str): The secret key for decryption.

    Returns:
        str|bool: The decrypted plaintext data, or False if
            decryption fails.
    """
    h = hashlib.sha256(secret.encode("utf-8")).digest()
    aes = pyaes.AESModeOfOperationCTR(h)
    try:
        return aes.decrypt(unhexlify(data.encode("utf-8"))).decode("utf-8")
    except UnicodeDecodeError:
        return False


def encrypt(public_key: str, message: str) -> typing.Tuple[str, str]:
    """
    Encrypts a message using a public key.

    Args:
        public_key (str): The base64-encoded public key.
        message (str): The plaintext message to encrypt.

    Returns:
        tuple: A tuple containing the base64-encoded R value and the encrypted
            message as a hexadecimal string.
    """
    tmp_prk = secrets.randbelow(N)
    R = point_multiply(tmp_prk, G)

    S = point_multiply(tmp_prk, b64decode(public_key))
    secret = hashlib.sha256(S[0].to_bytes(32, "big")).hexdigest()
    return b64encode(R), aes_encrypt(message, secret)


def decrypt(private_key: int, R: str, ciphered: str) -> str:
    """
    Decrypts a message using a private key.

    Args:
        private_key (int): The base64-encoded private key.
        R (str): The base64-encoded ephemeral public key.
        ciphered (str): The ciphered message to decrypt.

    Returns:
        str: Message as plaintext.
    """
    S = point_multiply(private_key, b64decode(R))
    secret = hashlib.sha256(S[0].to_bytes(32, "big")).hexdigest()
    return aes_decrypt(ciphered, secret)


def dump_secret(secret: str = None) -> None:
    """
    Securely stores a secret using a PIN.

    The secret is encrypted with AES using a key derived from a PIN.
    The encrypted file is saved in a specified directory.

    Args:
        secret (str): The secret to be encrypted and stored.
    """
    secret = secret or getpass.getpass("Paste your secret here > ")
    # Loop to validate the PIN input as numeric only
    pincode = "?"
    while not re.match(r"^\d*$", pincode):
        pincode = getpass.getpass("type your pincode > ")
    # Generate the file path using the SHA256 hash of the PIN
    filename = os.path.join(
        KEYS, f"{hashlib.sha256(pincode.encode('utf-8')).hexdigest()}.key"
    )
    # Create necessary directories if they don't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    # Encrypt the secret and write it to the file
    with open(filename, "wb") as output:
        output.write(
            aes_encrypt(secret, bip39_hash(pincode).hex()).encode("utf-8")
        )


def load_secret() -> typing.Optional[str]:
    """Loads and decrypts a secret using a PIN.

    The file containing the secret is identified by a SHA256 hash of the PIN.
    If the file exists, its contents are decrypted and returned.

    Returns:
        Optional[str]: The decrypted secret, or None if the file does not
            exist.
    """
    # Initialize the PIN to enter the validation loop
    pincode = "?"
    while not re.match(r"^\d*$", pincode):
        pincode = getpass.getpass("type your pincode > ")
    # Generate the file path using the SHA256 hash of the PIN
    filename = os.path.join(
        KEYS, f"{hashlib.sha256(pincode.encode('utf-8')).hexdigest()}.key"
    )
    # Check if the file exists
    if os.path.exists(filename):
        # Read, decrypt and return the file's contents
        with open(filename, "rb") as input_:
            secret = aes_decrypt(
                input_.read().decode("utf-8"), bip39_hash(pincode).hex()
            )
        return secret
    # Return None if the file does not exist


def raw_sign(message: str, secret: str = None, salt: str = "") -> str:
    """Signs a message using a private key derived from a secret and a salt.

    This function generates a private key based on the provided secret and salt
    using the BIP39 hashing method. It then creates a digital signature for the
    message using the ECDSA algorithm and SECP256k1 curve. The signature is
    returned as a concatenated hexadecimal string.

    Args:
        message (str): The message to sign.
        secret (str, optional): The secret used to derive the private key. If
            not provided, the function attempts to load a saved secret.
        salt (str, optional): An additional salt value to derive the private
            key.

    Returns:
        str: The hexadecimal-encoded signature as a single string, where the
            first 64 characters represent 'r' and the next 64 represent 's'.

    Example:
        >>> raw_sign("Hello, world!", secret="my_secret", salt="my_salt")
        'd2b7fbc6790b4f8e52e01d0c42c65a7...'
    """
    prk = int.from_bytes(bip39_hash(secret or load_secret(), salt)) % N
    r, s = b64decode(sign(message, prk))
    return f"{r:064x}{s:064x}"
