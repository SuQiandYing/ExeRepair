"""Verified CPU MD5/RC4/aPLib prefix filter. Imported only for runtime recovery."""

import numpy as np
from numba import njit, prange

K = np.array(
    [
        0xD76AA478,
        0xE8C7B756,
        0x242070DB,
        0xC1BDCEEE,
        0xF57C0FAF,
        0x4787C62A,
        0xA8304613,
        0xFD469501,
        0x698098D8,
        0x8B44F7AF,
        0xFFFF5BB1,
        0x895CD7BE,
        0x6B901122,
        0xFD987193,
        0xA679438E,
        0x49B40821,
        0xF61E2562,
        0xC040B340,
        0x265E5A51,
        0xE9B6C7AA,
        0xD62F105D,
        0x02441453,
        0xD8A1E681,
        0xE7D3FBC8,
        0x21E1CDE6,
        0xC33707D6,
        0xF4D50D87,
        0x455A14ED,
        0xA9E3E905,
        0xFCEFA3F8,
        0x676F02D9,
        0x8D2A4C8A,
        0xFFFA3942,
        0x8771F681,
        0x6D9D6122,
        0xFDE5380C,
        0xA4BEEA44,
        0x4BDECFA9,
        0xF6BB4B60,
        0xBEBFBC70,
        0x289B7EC6,
        0xEAA127FA,
        0xD4EF3085,
        0x04881D05,
        0xD9D4D039,
        0xE6DB99E5,
        0x1FA27CF8,
        0xC4AC5665,
        0xF4292244,
        0x432AFF97,
        0xAB9423A7,
        0xFC93A039,
        0x655B59C3,
        0x8F0CCC92,
        0xFFEFF47D,
        0x85845DD1,
        0x6FA87E4F,
        0xFE2CE6E0,
        0xA3014314,
        0x4E0811A1,
        0xF7537E82,
        0xBD3AF235,
        0x2AD7D2BB,
        0xEB86D391,
    ],
    dtype=np.uint32,
)
SHIFT = np.array(
    [7, 12, 17, 22] * 4
    + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4
    + [6, 10, 15, 21] * 4,
    dtype=np.uint32,
)


@njit
def md5_u32(value):
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif i < 32:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) & 15
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) & 15
        else:
            f = c ^ (b | (~d))
            g = (7 * i) & 15
        word = value if g == 0 else (0x80 if g == 1 else (32 if g == 14 else 0))
        v = (a + f + int(K[i]) + word) & 0xFFFFFFFF
        s = int(SHIFT[i])
        rot = ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + rot) & 0xFFFFFFFF
    words = (
        (a + 0x67452301) & 0xFFFFFFFF,
        (b + 0xEFCDAB89) & 0xFFFFFFFF,
        (c + 0x98BADCFE) & 0xFFFFFFFF,
        (d + 0x10325476) & 0xFFFFFFFF,
    )
    out = np.empty(16, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            out[i * 4 + j] = (words[i] >> (8 * j)) & 255
    return out


@njit
def rc4(data, key):
    s = np.arange(256, dtype=np.uint8)
    j = 0
    for i in range(256):
        j = (j + int(s[i]) + int(key[i % len(key)])) & 255
        tmp = s[i]
        s[i] = s[j]
        s[j] = tmp
    i = 0
    j = 0
    out = np.empty(len(data), dtype=np.uint8)
    for n in range(len(data)):
        i = (i + 1) & 255
        j = (j + int(s[i])) & 255
        tmp = s[i]
        s[i] = s[j]
        s[j] = tmp
        out[n] = data[n] ^ s[(int(s[i]) + int(s[j])) & 255]
    return out


@njit
def bit(data, pos, tag, left):
    if left == 0:
        if pos >= len(data):
            return -1, pos, tag, left
        tag = int(data[pos])
        pos += 1
        left = 8
    value = (tag >> 7) & 1
    tag = (tag << 1) & 255
    left -= 1
    return value, pos, tag, left


@njit
def gamma(data, pos, tag, left):
    value = 1
    for _ in range(31):
        v, pos, tag, left = bit(data, pos, tag, left)
        if v < 0:
            return -1, pos, tag, left
        value = (value << 1) | v
        v, pos, tag, left = bit(data, pos, tag, left)
        if v < 0:
            return -1, pos, tag, left
        if v == 0:
            return value, pos, tag, left
    return -2, pos, tag, left


@njit
def valid_prefix(data, max_output):
    pos = 1
    tag = 0
    left = 0
    out = 1
    state = 2
    previous = 0
    for _ in range(4096):
        v, pos, tag, left = bit(data, pos, tag, left)
        if v < 0:
            return True
        if v == 0:
            if pos >= len(data):
                return True
            pos += 1
            out += 1
            state = 2
        else:
            v, pos, tag, left = bit(data, pos, tag, left)
            if v < 0:
                return True
            if v == 0:
                off, pos, tag, left = gamma(data, pos, tag, left)
                if off == -1:
                    return True
                if off < 0:
                    return False
                off -= state
                if off < 0:
                    return False
                if off == 0:
                    off = previous
                    length, pos, tag, left = gamma(data, pos, tag, left)
                    if length == -1:
                        return True
                else:
                    if pos >= len(data):
                        return True
                    off = ((off - 1) << 8) | int(data[pos])
                    pos += 1
                    previous = off
                    length, pos, tag, left = gamma(data, pos, tag, left)
                    if length == -1:
                        return True
                    length += (
                        (1 if off >= 0x7D00 else 0)
                        + (1 if off >= 0x500 else 0)
                        + (2 if off < 0x80 else 0)
                    )
                if length < 0 or off <= 0 or off > out:
                    return False
                out += length
                state = 1
            else:
                v, pos, tag, left = bit(data, pos, tag, left)
                if v < 0:
                    return True
                if v == 0:
                    if pos >= len(data):
                        return True
                    val = int(data[pos])
                    pos += 1
                    off = val >> 1
                    if off == 0:
                        return False  # Large target cannot end in this prefix.
                    if off > out:
                        return False
                    previous = off
                    out += 2 + (val & 1)
                    state = 1
                else:
                    off = 0
                    for _ in range(4):
                        v, pos, tag, left = bit(data, pos, tag, left)
                        if v < 0:
                            return True
                        off = (off << 1) | v
                    if off > out:
                        return False
                    out += 1
                    state = 2
        if out > max_output:
            return False
    return False


@njit(parallel=True)
def scan(prefix, cipher, start, count, max_output):
    flags = np.zeros(count, dtype=np.uint8)
    for n in prange(count):
        key = np.empty(32, dtype=np.uint8)
        key[:16] = prefix
        key[16:] = md5_u32(start + n)
        clear = rc4(cipher, key)
        if valid_prefix(clear, max_output):
            flags[n] = 1
    return flags
