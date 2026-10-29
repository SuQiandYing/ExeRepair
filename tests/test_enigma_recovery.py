from __future__ import annotations

from hashlib import md5, sha256
from pathlib import Path
import struct

import pytest

from exerepair.formats.enigma import EnigmaFormatError, PEImage
from exerepair.application.enigma import EnigmaService
from exerepair.cli import main
from exerepair.formats.enigma_common import (
    Idea,
    crc32,
    decipher,
    fix_branches,
    lz_decompress,
    plausible_prefix,
    section_key,
)
from exerepair.formats.enigma_unpack import (
    Descriptor,
    StoredSection,
    decode_section,
    parse_configuration,
    recover_sections,
    search_salt,
    stored_sections,
)
from exerepair.formats import evb

FIXTURES = Path(__file__).with_name("fixtures") / "enigma"


def literal_stream(plain: bytes) -> bytes:
    result = bytearray([plain[0]])
    tag = None
    used = 8

    def bit(value: int) -> None:
        nonlocal tag, used
        if used == 8:
            tag = len(result)
            result.append(0)
            used = 0
        assert tag is not None
        result[tag] |= value << (7 - used)
        used += 1

    for value in plain[1:]:
        bit(0)
        result.append(value)
    for value in (1, 1, 0):
        bit(value)
    result.append(0)
    return bytes(result)


def test_enigma_algorithm_vectors() -> None:
    seed = bytes.fromhex("0d961f3742a264754b33b15078ac40e4")
    key = section_key(seed, 0x17E9532F)
    assert key[16:].hex() == "9e8bd381a281e4fd0c934dc36fb738e6"
    packed = bytes.fromhex("00a40170808ff7ec00")
    clear = decipher(bytes.fromhex("5596b7f6448a8aebd6"), key)
    assert clear == packed
    assert crc32(clear) == 0x23C734E7
    expanded = lz_decompress(packed, 512, True)
    assert sha256(expanded).hexdigest() == (
        "4c6474903705cb450bb6434c29e8854f17d8324efca1fdb9ee9008599060883a"
    )
    assert all(plausible_prefix(packed[:size], len(packed), 512) for size in range(10))
    assert not plausible_prefix(bytes((0, 0xE4)), 2, 512)

    data = bytearray.fromhex(
        "90e800000000ff2501000000ff2501000000e90100000000000000000000"
    )
    fixed = fix_branches(data)
    assert fixed[2:6] == (0xFFFFFFFF).to_bytes(4, "little")
    assert fixed[8:12] == (1).to_bytes(4, "little")
    assert fixed[14:18] == (5).to_bytes(4, "little")
    assert fixed[19:23] == ((1 - 18) & 0xFFFFFFFF).to_bytes(4, "little")

    idea = Idea(bytes.fromhex("00010002000300040005000600070008"))
    assert idea.encrypt_block(bytes.fromhex("0000000100020003")).hex() == "11fbed2b01986de5"
    assert idea.decrypt_block(bytes.fromhex("11fbed2b01986de5")) == bytes.fromhex(
        "0000000100020003"
    )
    for length, cipher in (
        (7, "1bc2f7fe863210"),
        (8, "cd9119c51031fbca"),
        (17, "cd9119c51031fbca5863ebf47cc1a2c82c"),
    ):
        assert idea.decrypt(bytes.fromhex(cipher)) == bytes(range(length))


def _pe_fixture() -> tuple[bytes, PEImage, bytes]:
    image = bytearray(0xC00)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<I", image, optional + 32, 0x1000)
    struct.pack_into("<I", image, optional + 36, 0x200)
    struct.pack_into("<I", image, optional + 56, 0x3000)
    struct.pack_into("<I", image, optional + 60, 0x400)
    struct.pack_into("<H", image, optional + 68, 3)
    section_table = optional + 0xE0
    for index, (name, rva, raw_offset) in enumerate(
        ((b".text", 0x1000, 0x400), (b".pack", 0x2000, 0x800))
    ):
        at = section_table + index * 40
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            at,
            name,
            0x400,
            rva,
            0x400,
            raw_offset,
            0,
            0,
            0,
            0,
            0x60000020,
        )
    image[0x400:0x800] = bytes(range(256)) * 4
    payload = b"0123456789abcdef"
    image[0x400:0x410] = payload
    pe = PEImage.parse(image)
    return bytes(image), pe, payload


def _configured_pe_fixture() -> tuple[bytes, PEImage, bytes]:
    image, pe, payload = _pe_fixture()
    descriptor = bytearray(80)
    descriptor[0] = 1
    struct.pack_into("<I", descriptor, 8, len(payload))
    struct.pack_into("<I", descriptor, 12, len(payload))
    struct.pack_into("<I", descriptor, 16, 0x1000)
    descriptor[20:36] = bytes(range(16))
    struct.pack_into("<I", descriptor, 36, 0x60000020)
    struct.pack_into("<I", descriptor, 60, crc32(payload))
    plain = bytearray(116)
    struct.pack_into("<I", plain, 16, 0)
    struct.pack_into("<I", plain, 24, 1)
    plain[28:108] = descriptor
    struct.pack_into("<I", plain, 108, 0)
    struct.pack_into("<I", plain, 112, 0)
    plain[:16] = md5(plain[16:]).digest()
    packed = literal_stream(bytes(plain))
    metadata_key = md5(image[0x400:0x800]).digest()
    cipher = decipher(packed, metadata_key)
    mutable = bytearray(image)
    at = 0x840
    struct.pack_into("<III", mutable, at, 1, len(cipher), len(plain))
    mutable[at + 12 : at + 28] = md5(cipher).digest()
    mutable[at + 28 : at + 28 + len(cipher)] = cipher
    return bytes(mutable), pe, payload


def test_metadata_and_section_recovery() -> None:
    image, pe, payload = _pe_fixture()
    descriptor = bytearray(80)
    descriptor[0] = 1
    struct.pack_into("<I", descriptor, 8, len(payload))
    struct.pack_into("<I", descriptor, 12, len(payload))
    struct.pack_into("<I", descriptor, 16, 0x1000)
    descriptor[20:36] = bytes(range(16))
    struct.pack_into("<I", descriptor, 36, 0x60000020)
    struct.pack_into("<I", descriptor, 60, crc32(payload))
    plain = bytearray(116)
    struct.pack_into("<I", plain, 16, 0)
    struct.pack_into("<I", plain, 24, 1)
    plain[28:108] = descriptor
    struct.pack_into("<I", plain, 108, 0)
    struct.pack_into("<I", plain, 112, 0)
    plain[:16] = md5(plain[16:]).digest()
    packed = literal_stream(bytes(plain))
    metadata_key = md5(image[0x400:0x800]).digest()
    cipher = decipher(packed, metadata_key)
    mutable = bytearray(image)
    at = 0x840
    struct.pack_into("<III", mutable, at, 1, len(cipher), len(plain))
    mutable[at + 12 : at + 28] = md5(cipher).digest()
    mutable[at + 28 : at + 28 + len(cipher)] = cipher
    raw = bytes(mutable)
    config = parse_configuration(raw, pe, 0x2040)
    assert config.context is None
    assert config.descriptors[0].rva == 0x1000
    sections = stored_sections(raw, pe, config)
    assert decode_section(sections[0]) == payload
    recovered = recover_sections(sections)
    assert recovered[0].bytes == payload


def test_salt_search_and_section_filter() -> None:
    plain = bytes.fromhex("00a40170808ff7ec00")
    seed = bytes.fromhex("0d961f3742a264754b33b15078ac40e4")
    salt = 0x17E9532F
    packed = plain
    descriptor = Descriptor(0, True, 9, len(packed), 512, 0x1000, 0x60000020, seed, crc32(packed))
    section = StoredSection(descriptor, decipher(packed, section_key(seed, salt)))
    assert search_salt((section,), start=salt, count=1) == salt
    assert decode_section(section, salt) == lz_decompress(packed, 512, True)


def test_evb_fixtures_and_path_guards() -> None:
    states = (FIXTURES / "evb_v1_states.bin").read_bytes()
    container = (FIXTURES / "evb_v1_container.bin").read_bytes()
    nodes = evb._interleaved_directory(container, states[:256])
    assert [(str(node.path), node.size, node.offset) for node in nodes] == [("GCR.key", 16, 301)]
    assert len(evb._stored_files(nodes, container, states[256:])[0].data) == 16

    states = (FIXTURES / "evb_states.bin").read_bytes()
    packed = (FIXTURES / "evb_directory.bin").read_bytes()
    metadata, content = states[:256], states[256:]
    expected = struct.unpack("<I", evb._decipher(packed[4:8], metadata))[0]
    tree = lz_decompress(evb._decipher(packed[8:], metadata), expected, True)
    nodes = evb._directory(tree)
    assert str(nodes[0].path) == "Scene.pck"
    data = evb._file_data((FIXTURES / "evb_content.bin").read_bytes(), 16385, False, content)
    assert sha256(data).hexdigest() == "2f84be9da56f8e25c400ba3dbc69caeb73953e53e10b0607bbc259eef48a4116"

    for name in ("../outside", "C:\\outside", "\\\\outside", "%SYSTEM%\\outside", "NUL.txt"):
        with pytest.raises(EnigmaFormatError, match="EVB"):
            evb._safe_path(Path(), name)


def test_enigma_service_writes_recovered_sections(tmp_path) -> None:
    image, _pe, payload = _configured_pe_fixture()
    source = tmp_path / "protected.exe"
    source.write_bytes(image)
    output = tmp_path / "unpack"

    messages = []
    result = EnigmaService().recover(
        source,
        metadata_rva=0x2040,
        backend="cpu",
        output_directory=output,
        progress=messages.append,
    )

    assert result.source_path == source.resolve()
    assert result.salt is None
    assert result.recovered_sections[0].bytes == payload
    assert result.evb_files == ()
    assert (output / "sections" / "section-000-00001000.bin").read_bytes() == payload
    assert source.read_bytes() == image
    assert any("已写出 1 个恢复节" in message for message in messages)


def test_enigma_cli_routes_inspection_and_recovery(tmp_path, capsys) -> None:
    image, _pe, payload = _configured_pe_fixture()
    source = tmp_path / "protected.exe"
    source.write_bytes(image)

    assert main([
        "--enigma",
        "--inspect",
        str(source),
        "--enigma-metadata-rva",
        "0x2040",
    ]) == 0
    inspection_output = capsys.readouterr().out
    assert "PE 位数: 32" in inspection_output
    assert "描述符数量: 1" in inspection_output

    output = tmp_path / "cli-unpack"
    assert main([
        "--enigma",
        str(source),
        "--enigma-metadata-rva",
        "0x2040",
        "--output",
        str(output),
    ]) == 0
    recovery_output = capsys.readouterr().out
    assert "section salt: 未加密" in recovery_output
    assert (output / "sections" / "section-000-00001000.bin").read_bytes() == payload