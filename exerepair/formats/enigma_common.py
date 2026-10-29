"""Portable primitives shared by the Enigma unpacking formats.

The Rust implementation keeps these routines independent from the Loader
instruction interpreter. The Python port follows the same boundary so that
configuration and EVB parsing can be used without importing optional runtime
or GPU dependencies.
"""

from __future__ import annotations

from hashlib import md5
import struct
import zlib

from .enigma import EnigmaFormatError

MAX_EXPANDED = 256 * 1024 * 1024
UINT32_MASK = 0xFFFFFFFF


def expanded_size(size: int) -> int:
    if not 0 < size <= MAX_EXPANDED:
        raise EnigmaFormatError(
            f"invalid expanded size {size:#x} (limit {MAX_EXPANDED:#x})"
        )
    return size


def crc32(data: bytes | bytearray | memoryview) -> int:
    """Return the IEEE CRC32 used by Enigma packed section descriptors."""

    return zlib.crc32(memoryview(data)) & UINT32_MASK


class _Bits:
    __slots__ = ("data", "pos", "bits", "remaining")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self.data = memoryview(data).cast("B")
        self.pos = 0
        self.bits = 0
        self.remaining = 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise EnigmaFormatError("truncated LZ input")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def bit(self) -> int:
        if self.remaining == 0:
            self.bits = self.byte()
            self.remaining = 8
        value = self.bits >> 7
        self.bits = (self.bits << 1) & 0xFF
        self.remaining -= 1
        return value

    def gamma(self) -> int:
        value = 1
        for _ in range(31):
            value = (value << 1) | self.bit()
            if self.bit() == 0:
                return value
        raise EnigmaFormatError("LZ gamma code exceeds 32 bits")


def _copy_lz(output: bytearray, distance: int, length: int, limit: int) -> None:
    if not 0 < distance <= len(output):
        raise EnigmaFormatError(f"invalid LZ distance {distance}")
    if length > limit - len(output):
        raise EnigmaFormatError("LZ output exceeds declared size")
    for _ in range(length):
        output.append(output[-distance])


def lz_decompress(
    data: bytes | bytearray | memoryview,
    expected: int,
    strict: bool = False,
) -> bytes:
    """Decode the Enigma LZ stream with a declared output bound.

    strict checks that the byte cursor reaches the end at the terminator.
    Loader and EVB block streams may have padding, while metadata and section
    streams use strict mode.
    """

    expanded_size(expected)
    bits = _Bits(data)
    output = bytearray([bits.byte()])
    lwm = 2
    previous = 0
    while True:
        if bits.bit() == 0:
            if len(output) >= expected:
                raise EnigmaFormatError("LZ literal exceeds declared size")
            output.append(bits.byte())
            lwm = 2
            continue

        if bits.bit() == 0:
            code = bits.gamma()
            if code < lwm:
                raise EnigmaFormatError("negative LZ distance code")
            distance_code = code - lwm
            lwm = 1
            if distance_code == 0:
                length = bits.gamma()
                _copy_lz(output, previous, length, expected)
            else:
                distance = ((distance_code - 1) << 8) | bits.byte()
                length = bits.gamma()
                length += int(distance >= 0x7D00)
                length += int(distance >= 0x500)
                length += 2 * int(distance < 0x80)
                _copy_lz(output, distance, length, expected)
                previous = distance
            continue

        if bits.bit() == 0:
            value = bits.byte()
            distance = value >> 1
            if distance == 0:
                if len(output) != expected:
                    raise EnigmaFormatError(
                        f"LZ expanded size mismatch: {len(output)} != {expected}"
                    )
                if strict and bits.pos != len(bits.data):
                    raise EnigmaFormatError("unconsumed bytes after LZ terminator")
                return bytes(output)
            _copy_lz(output, distance, 2 + (value & 1), expected)
            previous = distance
            lwm = 1
            continue

        distance = 0
        for _ in range(4):
            distance = (distance << 1) | bits.bit()
        if distance == 0:
            if len(output) >= expected:
                raise EnigmaFormatError("LZ zero literal exceeds declared size")
            output.append(0)
        else:
            _copy_lz(output, distance, 1, expected)
        lwm = 2


def plausible_prefix(
    data: bytes | bytearray | memoryview,
    packed_size: int,
    expected: int,
) -> bool:
    """Reject impossible LZ prefixes without expanding them.

    Exhausting a prefix is inconclusive and therefore returns True. This is
    deliberately weaker than lz_decompress and is safe to use only as a
    salt-search prefilter.
    """

    try:
        bits = _Bits(data)
        bits.byte()
        size, lwm, previous = 1, 2, 0
        while True:
            if bits.bit() == 0:
                bits.byte()
                size += 1
                lwm = 2
                if size > expected:
                    return False
                continue

            if bits.bit() == 0:
                code = bits.gamma()
                if code < lwm:
                    return False
                distance_code = code - lwm
                lwm = 1
                if distance_code == 0:
                    distance = previous
                    length = bits.gamma()
                else:
                    distance = ((distance_code - 1) << 8) | bits.byte()
                    length = bits.gamma()
                    length += int(distance >= 0x7D00)
                    length += int(distance >= 0x500)
                    length += 2 * int(distance < 0x80)
                    previous = distance
            elif bits.bit() == 0:
                value = bits.byte()
                distance = value >> 1
                length = 2 + (value & 1)
                if distance == 0:
                    return size == expected and bits.pos == packed_size
                previous = distance
                lwm = 1
            else:
                distance = 0
                for _ in range(4):
                    distance = (distance << 1) | bits.bit()
                if distance == 0:
                    size += 1
                    lwm = 2
                    if size > expected:
                        return False
                    continue
                length = 1
                lwm = 2

            if distance == 0 or distance > size or length > expected - size:
                return False
            size += length
    except (EnigmaFormatError, IndexError):
        return True


def fix_branches(data: bytes | bytearray | memoryview) -> bytes:
    """Apply the Enigma E8/E9/FF25 inverse transform."""

    out = bytearray(data)
    pos = 0
    counter = 0
    while pos + 6 < len(out):
        if out[pos] in (0xE8, 0xE9):
            old = struct.unpack_from("<I", out, pos + 1)[0]
            struct.pack_into("<I", out, pos + 1, (old - pos) & UINT32_MASK)
            pos += 5
        elif out[pos : pos + 2] == b"\xFF\x25":
            old = struct.unpack_from("<I", out, pos + 2)[0]
            struct.pack_into("<I", out, pos + 2, (old - counter) & UINT32_MASK)
            counter = (counter - 4) & UINT32_MASK
            pos += 6
        else:
            pos += 1
    return bytes(out)


class Rc4:
    __slots__ = ("state", "i", "j")

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        key_bytes = bytes(key)
        if not key_bytes:
            raise ValueError("RC4 key cannot be empty")
        self.state = list(range(256))
        self.i = 0
        self.j = 0
        for index in range(256):
            self.j = (self.j + self.state[index] + key_bytes[index % len(key_bytes)]) & 0xFF
            self.state[index], self.state[self.j] = self.state[self.j], self.state[index]
        self.j = 0

    def byte(self, value: int) -> int:
        self.i = (self.i + 1) & 0xFF
        self.j = (self.j + self.state[self.i]) & 0xFF
        self.state[self.i], self.state[self.j] = self.state[self.j], self.state[self.i]
        at = (self.state[self.i] + self.state[self.j]) & 0xFF
        return value ^ self.state[at]

    def apply(self, data: bytearray | memoryview) -> None:
        for index, value in enumerate(data):
            data[index] = self.byte(value)


def decipher(data: bytes | bytearray | memoryview, key: bytes | bytearray | memoryview) -> bytes:
    result = bytearray(data)
    Rc4(key).apply(result)
    return bytes(result)


def section_key(seed: bytes | bytearray | memoryview, salt: int) -> bytes:
    seed_bytes = bytes(seed)
    if len(seed_bytes) != 16:
        raise ValueError("Enigma section seeds must contain 16 bytes")
    return seed_bytes + md5(struct.pack("<I", salt & UINT32_MASK)).digest()


class SectionProbe:
    """Reusable RC4 KSA prefix for a stream of candidate salts."""

    __slots__ = ("_initial", "_initial_j", "_seed")

    def __init__(self, seed: bytes | bytearray | memoryview) -> None:
        self._seed = bytes(seed)
        if len(self._seed) != 16:
            raise ValueError("Enigma section seeds must contain 16 bytes")
        state = list(range(256))
        j = 0
        for index in range(16):
            j = (j + state[index] + self._seed[index]) & 0xFF
            state[index], state[j] = state[j], state[index]
        self._initial = tuple(state)
        self._initial_j = j

    def cipher(self, salt: int) -> Rc4:
        key = section_key(self._seed, salt)
        state = list(self._initial)
        j = self._initial_j
        for index in range(16, 256):
            j = (j + state[index] + key[index & 31]) & 0xFF
            state[index], state[j] = state[j], state[index]
        cipher = object.__new__(Rc4)
        cipher.state = state
        cipher.i = 0
        cipher.j = 0
        return cipher


def _idea_mul(a: int, b: int) -> int:
    left = 65536 if a == 0 else a
    right = 65536 if b == 0 else b
    return (left * right) % 65537


def _idea_inverse(value: int) -> int:
    base, exponent, result = value, 65535, 1
    while exponent:
        if exponent & 1:
            result = _idea_mul(result, base)
        base = _idea_mul(base, base)
        exponent >>= 1
    return result


def _idea_block(block: bytes, keys: tuple[int, ...]) -> bytes:
    values = list(struct.unpack(">4H", block))
    for round_index in range(8):
        at = round_index * 6
        values[0] = _idea_mul(values[0], keys[at]) & 0xFFFF
        values[1] = (values[1] + keys[at + 1]) & 0xFFFF
        values[2] = (values[2] + keys[at + 2]) & 0xFFFF
        values[3] = _idea_mul(values[3], keys[at + 3]) & 0xFFFF
        a = _idea_mul(keys[at + 4], values[0] ^ values[2]) & 0xFFFF
        b = _idea_mul(keys[at + 5], ((values[1] ^ values[3]) + a) & 0xFFFF) & 0xFFFF
        c = (a + b) & 0xFFFF
        values = [values[0] ^ b, values[2] ^ b, values[1] ^ c, values[3] ^ c]
    result = (
        _idea_mul(values[0], keys[48]) & 0xFFFF,
        (values[2] + keys[49]) & 0xFFFF,
        (values[1] + keys[50]) & 0xFFFF,
        _idea_mul(values[3], keys[51]) & 0xFFFF,
    )
    return struct.pack(">4H", *result)


class Idea:
    """IDEA with Enigma CBC feedback and unpadded partial tail."""

    __slots__ = ("_enc", "_dec")

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        key_bytes = bytes(key)
        if len(key_bytes) != 16:
            raise ValueError("IDEA keys must contain 16 bytes")
        state = int.from_bytes(key_bytes, "big")
        enc = []
        for index in range(52):
            if index and index % 8 == 0:
                state = ((state << 25) | (state >> 103)) & ((1 << 128) - 1)
            enc.append((state >> (112 - (index % 8) * 16)) & 0xFFFF)
        dec = [0] * 52
        for round_index in range(9):
            at = round_index * 6
            source = 48 - round_index * 6
            first = 1 if round_index in (0, 8) else 2
            second = 2 if round_index in (0, 8) else 1
            dec[at] = _idea_inverse(enc[source]) & 0xFFFF
            dec[at + 1] = (-enc[source + first]) & 0xFFFF
            dec[at + 2] = (-enc[source + second]) & 0xFFFF
            dec[at + 3] = _idea_inverse(enc[source + 3]) & 0xFFFF
            if round_index < 8:
                dec[at + 4] = enc[46 - round_index * 6]
                dec[at + 5] = enc[47 - round_index * 6]
        self._enc = tuple(enc)
        self._dec = tuple(dec)

    def encrypt_block(self, data: bytes | bytearray | memoryview) -> bytes:
        block = bytes(data)
        if len(block) != 8:
            raise ValueError("IDEA blocks must contain 8 bytes")
        return _idea_block(block, self._enc)

    def decrypt_block(self, data: bytes | bytearray | memoryview) -> bytes:
        block = bytes(data)
        if len(block) != 8:
            raise ValueError("IDEA blocks must contain 8 bytes")
        return _idea_block(block, self._dec)

    def decrypt(self, data: bytes | bytearray | memoryview) -> bytes:
        source = bytes(data)
        feedback = self.encrypt_block(b"\0" * 8)
        output = bytearray()
        for offset in range(0, len(source), 8):
            chunk = source[offset : offset + 8]
            if len(chunk) == 8:
                plain = self.decrypt_block(chunk)
                output.extend(a ^ b for a, b in zip(plain, feedback))
                feedback = chunk
            else:
                mask = self.encrypt_block(feedback)
                output.extend(a ^ b for a, b in zip(chunk, mask))
        return bytes(output)


__all__ = [
    "MAX_EXPANDED",
    "Idea",
    "Rc4",
    "SectionProbe",
    "crc32",
    "decipher",
    "expanded_size",
    "fix_branches",
    "lz_decompress",
    "plausible_prefix",
    "section_key",
]
