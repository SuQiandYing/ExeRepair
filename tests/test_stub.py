import io
import struct

import pytest

from exerepair.stub import (
    ContainerFlags,
    ContainerVersion,
    PatchMode,
    ContainerStub,
    ContainerParseResult,
    format_container_flags,
)
from tests.helpers import STUB_SPECS, encrypted_resource, make_stub


@pytest.mark.parametrize(
    ("version", "level"),
    [
        (0x00576453, ContainerVersion.V1),
        (0x32576453, ContainerVersion.V2),
        (0x33576453, ContainerVersion.V3),
        (0x34576453, ContainerVersion.V4),
        (0x35576453, ContainerVersion.V5),
        (0x36576453, ContainerVersion.V6),
        (0x37576453, ContainerVersion.V7),
    ],
)
def test_parse_every_supported_stub_version(version: int, level: ContainerVersion) -> None:
    _, _, _, patch_format, name_tail = STUB_SPECS[version]
    patch = {
        "file_name": "データ.bin" if patch_format != "v1" else "",
        "position": 0x280,
        "length": 0x20,
        "signature1": 0x11223344,
        "signature2": 0xAABBCCDD,
        "reserve1": 0x1234,
    }
    flags = int(ContainerFlags.UseTempPath)
    if name_tail:
        flags |= int(ContainerFlags.UseExecutableFileNameArgument)
    blob, align_size = make_stub(
        version, flags, [patch], executable_name="ゲーム.exe"
    )

    result, stub = ContainerStub.create_factory(io.BytesIO(blob))
    assert result is ContainerParseResult.Successed
    assert stub is not None
    assert stub.level is level
    assert stub.size == STUB_SPECS[version][0]
    assert stub.align_size == align_size
    assert len(stub.patches) == STUB_SPECS[version][2]
    assert stub.patches[0].position == 0x280
    assert stub.patches[0].mode is PatchMode.ExecutableOnly
    assert stub.executable_file_name == ("ゲーム.exe" if name_tail else "main.bin")


def test_stub_hash_and_version_errors() -> None:
    blob, _ = make_stub(0x34576453, 0)
    corrupted = bytearray(blob)
    corrupted[-1] ^= 1
    result, stub = ContainerStub.create_factory(corrupted)
    assert result is ContainerParseResult.StubHashInvalid
    assert stub is None

    unknown = struct.pack("<IIII", 0x12345678, 0, 0, 0)
    result, stub = ContainerStub.create_factory(unknown)
    assert result is ContainerParseResult.StubUnknowVersion
    assert stub is None


def test_decrypt_resource_checks_and_restores_signature() -> None:
    signature1 = 0x11223344
    signature2 = 0xAABBCCDD
    position = 0x2468
    plain = struct.pack("<I", signature1) + b"resource payload"
    encrypted = bytearray(encrypted_resource(plain, position, signature1, signature2))
    blob, _ = make_stub(0x34576453, 0)
    _, stub = ContainerStub.create_factory(blob)
    assert stub is not None
    assert stub.decrypt_resource(encrypted, position, signature1, signature2)
    assert encrypted == plain
    assert not stub.decrypt_resource(encrypted, position, signature1, signature2)


def test_flag_text_matches_dotnet_style() -> None:
    value = ContainerFlags.UseTempPath | ContainerFlags.AllowMultiProcess
    assert format_container_flags(value) == "AllowMultiProcess, UseTempPath"
    assert format_container_flags(0) == "0"
    assert format_container_flags(0x80000000) == str(0x80000000)
