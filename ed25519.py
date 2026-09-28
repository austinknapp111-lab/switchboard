"""
ed25519.py — pure-Python Ed25519 (sign + verify), vendored into Switchboard.

Zero-dependency implementation so the server runs on stdlib Python only.
Algorithm: Daniel J. Bernstein's Ed25519 (ref10 logic), ported in the style
of the well-known compact public-domain Python implementation.

Public API used by Switchboard:
    create_keypair() -> (secret_key: bytes[32], public_key: bytes[32])
    sign(secret_key: bytes[32], message: bytes) -> bytes[64]
    verify(public_key: bytes[32], message: bytes, signature: bytes[64]) -> bool
"""

import hashlib
import secrets

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493


def H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def inv(x: int) -> int:
    return pow(x, q - 2, q)


d = (-121665 * inv(121666)) % q
_i = pow(2, (q - 1) // 4, q)


def xrecover(y: int) -> int:
    xx = (y * y - 1) * inv(d * y * y + 1) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _i) % q
    if x % 2 != 0:
        x = q - x
    return x


By = (4 * inv(5)) % q
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)  # base point, extended coords
ident = (0, 1, 1, 0)


def edwards(P, Q):
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = ((y1 - x1) * (y2 - x2)) % q
    bb = ((y1 + x1) * (y2 + x2)) % q
    c = (t1 * 2 * d * t2) % q
    dd = (z1 * 2 * z2) % q
    e = (bb - a) % q
    f = (dd - c) % q
    g = (dd + c) % q
    h = (bb + a) % q
    return ((e * f) % q, (g * h) % q, (f * g) % q, (e * h) % q)


def scalarmult(P, e: int):
    if e == 0:
        return ident
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1:
        Q = edwards(Q, P)
    return Q


def encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def encodepoint(P) -> bytes:
    (x, y, z, _t) = P
    zi = inv(z)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _publickey(sk: bytes) -> bytes:
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    return encodepoint(scalarmult(B, a))


def _Hint(m: bytes) -> int:
    h = H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def _signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8:b // 4] + m)
    R = scalarmult(B, r)
    S = (r + _Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(b))


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(b - 1))
    x = xrecover(y)
    if _bit(s, b - 1):
        x = q - x
    P = (x, y, 1, (x * y) % q)
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        raise ValueError("point not on curve")
    return P


def _proj_eq(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % q == 0 and (P[1] * Q[2] - Q[1] * P[2]) % q == 0


def _checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    if len(sig) != b // 4:
        raise ValueError("bad signature length")
    if len(pk) != b // 8:
        raise ValueError("bad public key length")
    R = _decodepoint(sig[0:b // 8])
    A = _decodepoint(pk)
    S = _decodeint(sig[b // 8:b // 4])
    if S >= l:
        return False
    # R must lie in the prime-order subgroup (small-order R would allow
    # signature malleability). Honest signers produce R = r*B of order l,
    # so l*R == identity; anything else is rejected.
    if not _proj_eq(scalarmult(R, l), ident):
        return False
    h = _Hint(encodepoint(R) + pk + m)
    v1 = scalarmult(B, S)
    v2 = edwards(R, scalarmult(A, h))
    return _proj_eq(v1, v2)


# ---------------------------------------------------------------- public API


def create_keypair():
    """Return (secret_key, public_key), each 32 bytes."""
    sk = secrets.token_bytes(32)
    return sk, _publickey(sk)


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign message with a 32-byte secret key. Returns 64-byte signature."""
    if len(secret_key) != 32:
        raise ValueError("secret key must be 32 bytes")
    return _signature(bytes(message), bytes(secret_key), _publickey(secret_key))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte signature over message with a 32-byte public key."""
    try:
        return _checkvalid(bytes(signature), bytes(message), bytes(public_key))
    except Exception:
        return False


def public_key_from_secret(secret_key: bytes) -> bytes:
    if len(secret_key) != 32:
        raise ValueError("secret key must be 32 bytes")
    return _publickey(bytes(secret_key))
