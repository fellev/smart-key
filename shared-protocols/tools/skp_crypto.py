"""Reference implementation of the SmartKey (SKP1) crypto primitives.

Pure python standard library only (hashlib / hmac + a compact X25519), so that the
test vectors can be regenerated anywhere without installing anything.

This module is the executable companion of ../protocol-spec.md and ../pairing-spec.md.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

# ---------------------------------------------------------------- constants

VERSION = 0x01

INFO_BEACON = b"SKP1-beacon"
INFO_AUTH = b"SKP1-auth"
INFO_SESSION = b"SKP1-session"
INFO_PSEUDO = b"SKP1-pseudo"
TRANSCRIPT_AUTH = b"SKP1-auth-v1"
TRANSCRIPT_PAIR = b"SKP1-pair-v1"

DOMAIN_AUTH_PHONE = 0x01
DOMAIN_AUTH_LOCK = 0x02
DOMAIN_SESSION_ID = 0x03
DOMAIN_UNLOCK_EVENT = 0x10
DOMAIN_PAIR_CONFIRM_LOCK = 0x01
DOMAIN_PAIR_CONFIRM_PHONE = 0x02

BEACON_EPOCH_SECONDS = 15
PSEUDONYM_SIZE = 6
SESSION_ID_SIZE = 8


# ---------------------------------------------------------------- HKDF

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 extract-then-expand."""
    prk = hmac_sha256(salt if salt else b"\x00" * 32, ikm)
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


# ---------------------------------------------------------------- sub keys

def derive_subkeys(ltk: bytes, lock_id: bytes, user_id: bytes) -> dict:
    salt = lock_id + user_id
    return {
        "k_beacon": hkdf_sha256(ltk, salt, INFO_BEACON, 32),
        "k_auth": hkdf_sha256(ltk, salt, INFO_AUTH, 32),
    }


def pseudonym(k_beacon: bytes, epoch: int) -> bytes:
    data = INFO_PSEUDO + struct.pack("<Q", epoch)
    return hmac_sha256(k_beacon, data)[:PSEUDONYM_SIZE]


def epoch_for(unix_seconds: int) -> int:
    return unix_seconds // BEACON_EPOCH_SECONDS


# ---------------------------------------------------------------- handshake

def auth_transcript(lock_id: bytes, user_id: bytes, nonce_l: bytes, nonce_p: bytes) -> bytes:
    return TRANSCRIPT_AUTH + lock_id + user_id + nonce_l + nonce_p


def tag_phone(k_auth: bytes, transcript: bytes) -> bytes:
    return hmac_sha256(k_auth, bytes([DOMAIN_AUTH_PHONE]) + transcript)


def tag_lock(k_auth: bytes, transcript: bytes) -> bytes:
    return hmac_sha256(k_auth, bytes([DOMAIN_AUTH_LOCK]) + transcript)


def session_id(k_auth: bytes, transcript: bytes) -> bytes:
    return hmac_sha256(k_auth, bytes([DOMAIN_SESSION_ID]) + transcript)[:SESSION_ID_SIZE]


def session_key(k_auth: bytes, lock_id: bytes, user_id: bytes,
                nonce_l: bytes, nonce_p: bytes) -> bytes:
    return hkdf_sha256(k_auth, nonce_l + nonce_p, INFO_SESSION + lock_id + user_id, 32)


def unlock_tag(k_sess: bytes, sid: bytes, counter: int, result: int) -> bytes:
    data = bytes([DOMAIN_UNLOCK_EVENT]) + sid + struct.pack("<I", counter) + bytes([result])
    return hmac_sha256(k_sess, data)


# ---------------------------------------------------------------- pairing

def pair_transcript(lock_id: bytes, user_id: bytes, pub_p: bytes, pub_l: bytes,
                    nonce_p: bytes, nonce_l: bytes) -> bytes:
    return TRANSCRIPT_PAIR + lock_id + user_id + pub_p + pub_l + nonce_p + nonce_l


def pair_ltk(shared_z: bytes, nonce_p: bytes, nonce_l: bytes,
             transcript: bytes, pairing_code: str) -> bytes:
    return hkdf_sha256(shared_z, nonce_p + nonce_l,
                       transcript + pairing_code.encode("ascii"), 32)


def pair_confirm_lock(ltk: bytes, transcript: bytes) -> bytes:
    return hmac_sha256(ltk, bytes([DOMAIN_PAIR_CONFIRM_LOCK]) + transcript)


def pair_confirm_phone(ltk: bytes, transcript: bytes) -> bytes:
    return hmac_sha256(ltk, bytes([DOMAIN_PAIR_CONFIRM_PHONE]) + transcript)


# ---------------------------------------------------------------- X25519 (RFC 7748)

_P = 2 ** 255 - 19
_A24 = 121665


_MASK255 = (1 << 255) - 1


def _cswap(swap: int, x2: int, x3: int):
    dummy = (-swap) & _MASK255 & (x2 ^ x3)
    return x2 ^ dummy, x3 ^ dummy


def _decode_scalar(k: bytes) -> int:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748 X25519 scalar multiplication."""
    k = _decode_scalar(scalar)
    u = int.from_bytes(u_bytes, "little") % (2 ** 255)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + _A24 * e) % _P) % _P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_BASE_POINT = (9).to_bytes(32, "little")


def x25519_public(private_key: bytes) -> bytes:
    return x25519(private_key, _BASE_POINT)
