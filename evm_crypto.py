"""Pure-stdlib Ethereum crypto for Switchboard wallet auth.

No third-party dependencies — the Switchboard image is stdlib-only.
Provides:
  - keccak_256      : Keccak-256 (NOT NIST SHA3-256; different padding)
  - personal_hash   : EIP-191 personal_sign message hash
  - ecrecover       : secp256k1 public-key recovery -> 20-byte address
  - is_valid_address: 0x + 40 hex check + checksum-agnostic normalize

Used for Sign-In-With-Ethereum style wallet linking and for verifying
Base (chain id 8453) USDC payment receipts. Never handles private keys.
"""

# ---------------------------------------------------------------- keccak-256

_MASK64 = 0xFFFFFFFFFFFFFFFF

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_KECCAK_ROTC = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)

_KECCAK_PILAN = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)


def _rol64(x, n):
    n %= 64
    if n == 0:
        return x & _MASK64
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(s):
    """Keccak-f[1600] permutation. s: list of 25 ints, mutated in place."""
    bc = [0] * 5
    for rnd in _KECCAK_RC:
        # theta
        for i in range(5):
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rol64(bc[(i + 1) % 5], 1)
            for j in range(5):
                s[i + 5 * j] ^= t
        # rho + pi
        t = s[1]
        for i in range(24):
            j = _KECCAK_PILAN[i]
            bc[0] = s[j]
            s[j] = _rol64(t, _KECCAK_ROTC[i])
            t = bc[0]
        # chi
        for j in range(0, 25, 5):
            for i in range(5):
                bc[i] = s[j + i]
            for i in range(5):
                s[j + i] ^= (~bc[(i + 1) % 5] & bc[(i + 2) % 5]) & _MASK64
                s[j + i] &= _MASK64
        # iota
        s[0] ^= rnd


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 digest (Ethereum variant, pad10*1 with 0x01 domain)."""
    rate = 136  # bytes (1088-bit rate)
    st = [0] * 25
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] |= 0x80
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            word = int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
            st[i] ^= word
        _keccak_f(st)
    return b"".join(w.to_bytes(8, "little") for w in st[:4])


# --------------------------------------------------------------- secp256k1

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
# Gy: even square root of x^3 + 7 (p % 4 == 3, so sqrt via pow)
_GY = pow((_GX * _GX * _GX + 7) % _P, (_P + 1) // 4, _P)
if _GY & 1:
    _GY = _P - _GY
_G = (_GX, _GY)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 * pow(2 * y1, _P - 2, _P)) % _P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, _P - 2, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _point_mul(k, point=_G):
    result = None
    while k > 0:
        if k & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        k >>= 1
    return result


def _pub_to_address(point) -> bytes:
    x, y = point
    return keccak_256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


def personal_hash(message: bytes) -> bytes:
    """EIP-191 personal_sign hash of a message."""
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode()
    return keccak_256(prefix + message)


def ecrecover(msg_hash: bytes, v: int, r: int, s: int) -> bytes:
    """Recover the 20-byte signer address from a 65-byte-style signature.

    msg_hash: 32-byte keccak of the signed payload (e.g. personal_hash).
    v: 27/28 (or 0/1/2/3 recovery id).
    Raises ValueError on invalid input.
    """
    if len(msg_hash) != 32:
        raise ValueError("msg_hash must be 32 bytes")
    if not (1 <= r < _N and 1 <= s < _N):
        raise ValueError("r/s out of range")
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1, 2, 3):
        raise ValueError("bad v")
    x = r + (recid >> 1) * _N
    if x >= _P:
        raise ValueError("x out of range")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y * y) % _P != y_sq:
        raise ValueError("x is not on the curve")
    if (y & 1) != (recid & 1):
        y = _P - y
    r_point = (x, y)
    e = int.from_bytes(msg_hash, "big") % _N
    r_inv = pow(r, _N - 2, _N)
    # Q = r^-1 * (s*R - e*G)
    q = _point_mul(r_inv, _point_add(_point_mul(s, r_point),
                                    _point_mul((-e) % _N, _G)))
    if q is None:
        raise ValueError("recovery failed")
    return _pub_to_address(q)


def is_valid_address(addr: str) -> bool:
    return (isinstance(addr, str) and len(addr) == 42
            and addr.startswith(("0x", "0X"))
            and all(c in "0123456789abcdefABCDEF" for c in addr[2:]))


def normalize_address(addr: str) -> str:
    """Lowercase 0x address. (No EIP-55 checksum — comparisons are
    case-insensitive everywhere in this module's callers.)"""
    return "0x" + addr[2:].lower()


# ------------------------------------------------------- self-test (dev)

def _self_test():
    import secrets
    # 1. keccak-256("") — well-known vector
    assert keccak_256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", \
        "keccak vector mismatch"
    # 2. n * G == infinity
    assert _point_mul(_N) is None, "n*G should be infinity"
    # 3. sign/recover round-trip with a random key
    priv = secrets.randbelow(_N - 1) + 1
    pub = _point_mul(priv)
    addr = _pub_to_address(pub)
    msg = b"Switchboard wallet self-test"
    h = personal_hash(msg)
    e = int.from_bytes(h, "big")
    r = s = None
    recid = None
    k = secrets.randbelow(_N - 1) + 1
    R = _point_mul(k)
    r = R[0] % _N
    assert r != 0
    s = (pow(k, _N - 2, _N) * (e + r * priv)) % _N
    assert s != 0
    recid = (R[1] & 1)
    got = ecrecover(h, 27 + recid, r, s)
    assert got == addr, f"recovery mismatch: {got.hex()} != {addr.hex()}"
    # 4. wrong message must NOT recover the same address
    got2 = ecrecover(personal_hash(b"tampered"), 27 + recid, r, s)
    assert got2 != addr, "recovery should differ for tampered message"
    # 5. address helpers
    assert is_valid_address("0x" + addr.hex())
    assert not is_valid_address("0xZZZ")
    print("evm_crypto self-test: all checks passed")


if __name__ == "__main__":
    _self_test()
