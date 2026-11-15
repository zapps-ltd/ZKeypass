"""Twofish, in pure Python, for KeePass databases that use it.

The cryptography package has no Twofish, and KeePassXC offers Twofish as a
database cipher, so it is implemented here from the published specification
(Schneier, Kelsey, Whiting, Wagner, Hall and Ferguson, 1998).  It is checked
against the official known-answer vectors in tests/twofishtest.py.

The key-dependent S-boxes and the MDS multiplication are folded into four
256-entry tables when a key is set up, so each round costs table lookups
and additions only.  That makes a 100 KB database body take a fraction of
a second, which is plenty for password databases.

Only the block function, ECB and CBC with PKCS#7 padding are offered,
because that is all the KeePass formats need.
"""

import struct

__all__ = ["Twofish", "cbc_encrypt", "cbc_decrypt"]

_MASK = 0xFFFFFFFF

_Q0 = ((0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
       (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
       (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
       (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA))
_Q1 = ((0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
       (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
       (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
       (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA))

_MDS = ((0x01, 0xEF, 0x5B, 0x5B),
        (0x5B, 0xEF, 0xEF, 0x01),
        (0xEF, 0x5B, 0x01, 0xEF),
        (0xEF, 0x01, 0xEF, 0x5B))
_RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
       (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
       (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
       (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))


def _ror4(value, count):
    return ((value >> count) | (value << (4 - count))) & 0xF


def _make_q(tables):
    result = []
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ _ror4(b0, 1) ^ (8 * a0)) & 0xF
        a2, b2 = tables[0][a1], tables[1][b1]
        a3 = a2 ^ b2
        b3 = (a2 ^ _ror4(b2, 1) ^ (8 * a2)) & 0xF
        a4, b4 = tables[2][a3], tables[3][b3]
        result.append((b4 << 4) | a4)
    return tuple(result)


Q0 = _make_q(_Q0)
Q1 = _make_q(_Q1)


def _gf_mult(a, b, modulus):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= modulus
        b >>= 1
    return result


# Each MDS column as a 256-entry table of 32-bit words.
_MDS_COLUMNS = tuple(
    tuple(sum(_gf_mult(byte, _MDS[row][column], 0x169) << (8 * row)
              for row in range(4)) for byte in range(256))
    for column in range(4))


def _rol(value, count):
    return ((value << count) | (value >> (32 - count))) & _MASK


def _ror(value, count):
    return ((value >> count) | (value << (32 - count))) & _MASK


def _h_bytes(x, words):
    """The h function, byte by byte, before the MDS step."""
    y = [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF]
    k = len(words)

    def byte(word, index):
        return (word >> (8 * index)) & 0xFF

    if k == 4:
        y = [Q1[y[0]] ^ byte(words[3], 0), Q0[y[1]] ^ byte(words[3], 1),
             Q0[y[2]] ^ byte(words[3], 2), Q1[y[3]] ^ byte(words[3], 3)]
    if k >= 3:
        y = [Q1[y[0]] ^ byte(words[2], 0), Q1[y[1]] ^ byte(words[2], 1),
             Q0[y[2]] ^ byte(words[2], 2), Q0[y[3]] ^ byte(words[2], 3)]
    l0, l1 = words[0], words[1]
    return [Q1[Q0[Q0[y[0]] ^ byte(l1, 0)] ^ byte(l0, 0)],
            Q0[Q0[Q1[y[1]] ^ byte(l1, 1)] ^ byte(l0, 1)],
            Q1[Q1[Q0[y[2]] ^ byte(l1, 2)] ^ byte(l0, 2)],
            Q0[Q1[Q1[y[3]] ^ byte(l1, 3)] ^ byte(l0, 3)]]


def _h(x, words):
    y = _h_bytes(x, words)
    return (_MDS_COLUMNS[0][y[0]] ^ _MDS_COLUMNS[1][y[1]]
            ^ _MDS_COLUMNS[2][y[2]] ^ _MDS_COLUMNS[3][y[3]])


class Twofish:
    """One Twofish key.  encrypt_block and decrypt_block take 16 bytes."""

    def __init__(self, key):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish keys are 16, 24 or 32 bytes long.")
        k = len(key) // 8
        words = struct.unpack(f"<{2 * k}I", key)
        even, odd = words[0::2], words[1::2]
        s_words = []
        for index in range(k):
            chunk = key[8 * index:8 * index + 8]
            s = 0
            for row in range(4):
                value = 0
                for column in range(8):
                    value ^= _gf_mult(chunk[column], _RS[row][column], 0x14D)
                s |= value << (8 * row)
            s_words.append(s)
        s_words.reverse()

        rho = 0x01010101
        subkeys = []
        for index in range(20):
            a = _h((2 * index * rho) & _MASK, even)
            b = _rol(_h(((2 * index + 1) * rho) & _MASK, odd), 8)
            subkeys.append((a + b) & _MASK)
            subkeys.append(_rol((a + 2 * b) & _MASK, 9))
        self.k = tuple(subkeys)

        # g(X) = S0[x0] ^ S1[x1] ^ S2[x2] ^ S3[x3], one table per byte.
        tables = [[0] * 256 for _ in range(4)]
        for byte in range(256):
            x = byte | (byte << 8) | (byte << 16) | (byte << 24)
            y = _h_bytes(x, s_words)
            for position in range(4):
                tables[position][byte] = _MDS_COLUMNS[position][y[position]]
        self.s = tuple(tuple(table) for table in tables)

    def _g(self, x):
        s0, s1, s2, s3 = self.s
        return (s0[x & 0xFF] ^ s1[(x >> 8) & 0xFF]
                ^ s2[(x >> 16) & 0xFF] ^ s3[x >> 24])

    def encrypt_block(self, block):
        k, g = self.k, self._g
        r0, r1, r2, r3 = struct.unpack("<4I", block)
        r0 ^= k[0]
        r1 ^= k[1]
        r2 ^= k[2]
        r3 ^= k[3]
        for round_ in range(16):
            t0 = g(r0)
            t1 = g(((r1 << 8) | (r1 >> 24)) & _MASK)
            f0 = (t0 + t1 + k[2 * round_ + 8]) & _MASK
            f1 = (t0 + 2 * t1 + k[2 * round_ + 9]) & _MASK
            r2 = _ror(r2 ^ f0, 1)
            r3 = (((r3 << 1) | (r3 >> 31)) & _MASK) ^ f1
            r0, r1, r2, r3 = r2, r3, r0, r1
        return struct.pack("<4I", r2 ^ k[4], r3 ^ k[5], r0 ^ k[6], r1 ^ k[7])

    def decrypt_block(self, block):
        k, g = self.k, self._g
        c0, c1, c2, c3 = struct.unpack("<4I", block)
        r2, r3, r0, r1 = c0 ^ k[4], c1 ^ k[5], c2 ^ k[6], c3 ^ k[7]
        for round_ in range(15, -1, -1):
            r0, r1, r2, r3 = r2, r3, r0, r1
            t0 = g(r0)
            t1 = g(((r1 << 8) | (r1 >> 24)) & _MASK)
            f0 = (t0 + t1 + k[2 * round_ + 8]) & _MASK
            f1 = (t0 + 2 * t1 + k[2 * round_ + 9]) & _MASK
            r2 = ((r2 << 1) | (r2 >> 31)) & _MASK ^ f0
            r3 = _ror(r3 ^ f1, 1)
        return struct.pack("<4I", r0 ^ k[0], r1 ^ k[1], r2 ^ k[2], r3 ^ k[3])


def _xor(left, right):
    return (int.from_bytes(left, "little") ^ int.from_bytes(right, "little")
            ).to_bytes(16, "little")


def cbc_encrypt(key, iv, plain):
    """Twofish-CBC with PKCS#7 padding, as KeePass uses it."""
    cipher = Twofish(key)
    pad = 16 - len(plain) % 16
    plain = bytes(plain) + bytes([pad]) * pad
    out = bytearray()
    previous = bytes(iv)
    for offset in range(0, len(plain), 16):
        previous = cipher.encrypt_block(_xor(plain[offset:offset + 16], previous))
        out += previous
    return bytes(out)


def cbc_decrypt(key, iv, data):
    """Twofish-CBC; returns the plain text with the padding still on."""
    if len(data) % 16:
        raise ValueError("Twofish-CBC data is not a whole number of blocks.")
    cipher = Twofish(key)
    out = bytearray()
    previous = bytes(iv)
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        out += _xor(cipher.decrypt_block(block), previous)
        previous = block
    return bytes(out)
