from __future__ import annotations

import struct

from exerepair.program import WrappedProgram
from exerepair.stub import ContainerFlags, PatchMode
from tests.helpers import (
    encrypted_resource,
    make_embedded_wrapper,
    make_external_wrapper,
    make_pe,
    make_stub,
)


def _place_block(image: bytearray, offset: int, block: bytes) -> None:
    image[offset : offset + len(block)] = block


def test_embedded_executable_and_multiple_resource_patches(tmp_path) -> None:
    sig1 = 0x11223344
    sig2 = 0xAABBCCDD
    executable = make_pe(32)

    exe_plain = struct.pack("<I", sig1) + b"EXE-FILE"
    memory_plain = struct.pack("<I", sig1) + b"EXE-MEM!"
    _place_block(executable, 0x240, encrypted_resource(exe_plain, 0x240, sig1, sig2))
    _place_block(
        executable,
        0x280,
        encrypted_resource(memory_plain, 0x1080, sig1, sig2),
    )

    resource = bytearray(b"R" * 80)
    resource_plain1 = struct.pack("<I", sig1) + b"RESOURCE"
    resource_plain2 = struct.pack("<I", sig1) + b"SECOND!!"
    _place_block(
        resource,
        8,
        encrypted_resource(resource_plain1, 8, sig1, sig2),
    )
    _place_block(
        resource,
        40,
        encrypted_resource(resource_plain2, 40, sig1, sig2),
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "resource.bin").write_bytes(resource)

    patches = [
        {
            "file_name": "game.exe",
            "position": 0x240,
            "length": len(exe_plain),
            "signature1": sig1,
            "signature2": sig2,
        },
        {
            "position": 0x1080,
            "length": len(memory_plain),
            "signature1": sig1,
            "signature2": sig2,
        },
        {
            "file_name": r"data\resource.bin",
            "position": 8,
            "length": len(resource_plain1),
            "signature1": sig1,
            "signature2": sig2,
        },
        {
            "file_name": r"data\resource.bin",
            "position": 40,
            "length": len(resource_plain2),
            "signature1": sig1,
            "signature2": sig2,
        },
    ]
    blob, align_size = make_stub(
        0x34576453,
        int(ContainerFlags.UseExecutableFileNameArgument),
        patches,
        executable_name="game.exe",
    )
    wrapper_path = tmp_path / "wrapped.exe"
    wrapper_path.write_bytes(make_embedded_wrapper(blob, align_size, executable))

    program = WrappedProgram()
    assert program.load(wrapper_path), program.last_error
    assert program.executable_version == "PE32"
    assert program.stub is not None
    assert [patch.mode for patch in program.stub.patches[:4]] == [
        PatchMode.File,
        PatchMode.Memory,
        PatchMode.File,
        PatchMode.File,
    ]

    output = tmp_path / "output"
    assert program.extract(output), program.last_error
    extracted_executable = (output / "wrapped.exe").read_bytes()
    assert extracted_executable[0x240 : 0x240 + len(exe_plain)] == exe_plain
    assert extracted_executable[0x280 : 0x280 + len(memory_plain)] == memory_plain

    extracted_resource = (output / "data" / "resource.bin").read_bytes()
    assert extracted_resource[8 : 8 + len(resource_plain1)] == resource_plain1
    assert extracted_resource[40 : 40 + len(resource_plain2)] == resource_plain2
    assert program.last_error == ""


def test_external_executable_mode(tmp_path) -> None:
    executable = bytes(make_pe(64))
    (tmp_path / "real.exe").write_bytes(executable)
    blob, _ = make_stub(
        0x33576453,
        int(ContainerFlags.ExecutableFileNotPack),
        executable_name="real.exe",
    )
    wrapper_path = tmp_path / "launcher.exe"
    wrapper_path.write_bytes(make_external_wrapper(blob))

    program = WrappedProgram()
    assert program.load(wrapper_path), program.last_error
    assert program.executable_version == "PE64"
    assert program.extract()
    assert (tmp_path / "Recovered" / "launcher.exe").read_bytes() == executable


def test_executable_only_patch_and_failed_signature(tmp_path) -> None:
    sig1 = 0x01020304
    sig2 = 0x05060708
    executable = make_pe(32)
    plain = struct.pack("<I", sig1) + b"PAYLOAD!"
    _place_block(executable, 0x250, encrypted_resource(plain, 0x250, sig1, sig2))
    patches = [
        {
            "file_name": "ignored.bin",
            "position": 0x250,
            "length": len(plain),
            "signature1": sig1,
            "signature2": sig2,
        },
        {
            "position": 0x270,
            "length": 8,
            "signature1": sig1,
            "signature2": sig2,
        },
    ]
    blob, align_size = make_stub(
        0x34576453, int(ContainerFlags.UseTempPath), patches
    )
    wrapper_path = tmp_path / "wrapped.exe"
    wrapper_path.write_bytes(make_embedded_wrapper(blob, align_size, executable))

    program = WrappedProgram()
    assert program.load(wrapper_path)
    assert not program.extract()
    assert program.last_error == "1, "
    output = (tmp_path / "Recovered" / "wrapped.exe").read_bytes()
    assert output[0x250 : 0x250 + len(plain)] == plain


def test_load_error_messages_are_stable(tmp_path) -> None:
    program = WrappedProgram()
    assert not program.load(tmp_path / "missing.exe")
    assert program.last_error == "容器主程序文件不存在"

    invalid = tmp_path / "invalid.exe"
    invalid.write_bytes(b"not a PE")
    assert not program.load(invalid)
    assert program.last_error == "容器主程序仅支持32位"
