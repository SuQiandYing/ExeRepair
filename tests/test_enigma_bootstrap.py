"""Synthetic bootstrap regression: no-op XOR loops are not decoder layers."""

import struct

import pytest

from exerepair.formats.enigma import EnigmaFormatError, decode_enigma_bootstrap
from tests.helpers import make_pe


def _decoder(relative: int, length: int, key: int) -> bytes:
    return (
        b"\xb8" + struct.pack("<I", 0x1000) + b"\x03\xc5\x81\xc0"
        + struct.pack("<I", relative) + b"\xb9" + struct.pack("<I", length)
        + b"\xba" + struct.pack("<I", key)
        + bytes.fromhex("301040490f85f6ffffffe904000000")
        + bytes(10)
    )


def bootstrap_fixture(*, ambiguous: bool = False) -> bytes:
    data = make_pe(32, raw_size=0x800)
    optional = 0x80 + 24
    struct.pack_into("<I", data, optional + 0x10, 0x1000)
    struct.pack_into("<I", data, optional + 0x1C, 0x400000)
    struct.pack_into("<II", data, optional + 0x20, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 0x38, 0x2000, 0x200)
    code = bytearray(0x800)
    code[:38] = (
        b"\xeb\x08" + bytes(8)
        + b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x10\x00\x00\x00\x81\xed"
        + struct.pack("<I", 0x1000) + b"\xe9\x04\x00\x00\x00" + bytes(4)
    )
    for position, decoder in (
        (0x26, _decoder(0x80, 0x300, 0x9B)),
        (0x90, _decoder(0x210, 0x180, 7 if ambiguous else 0)),
        (0xE0, _decoder(0x240, 0xC0, 9)),
    ):
        code[position:position + len(decoder)] = decoder
    marker = b"The Enigma Protector version 1.31\0"
    code[0x280:0x280 + len(marker)] = marker
    for index in range(0x240, 0x300):
        code[index] ^= 9
    for index in range(0x80, 0x380):
        code[index] ^= 0x9B
    data[0x200:] = code
    return bytes(data)


def test_nested_decoder_ignores_zero_xor_loop_without_mutating_input():
    original = bootstrap_fixture()
    result = decode_enigma_bootstrap(original)
    assert result.version == "1.31"
    assert tuple(layer.xor_byte for layer in result.layers) == (0x9B, 9)
    assert b"The Enigma Protector version 1.31\0" in result.decoded_image
    assert original == bootstrap_fixture()


def test_two_real_mutating_layers_still_fail_closed():
    with pytest.raises(EnigmaFormatError, match="ambiguous.*2 candidates"):
        decode_enigma_bootstrap(bootstrap_fixture(ambiguous=True))
