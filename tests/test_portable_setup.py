"""Portable setup contracts and x86 ABI checks; all fixtures are synthetic."""
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from exerepair.api import PortableSetupProfile
from exerepair.domain.recovery import RecoveryError
from exerepair.workflows.disc_repair import build_disc_repair, disc_helper
from exerepair.workflows.portable_setup import (
    HELPER_CAPACITY, LITERAL_OFFSET, STUB_OFFSET, TEXT_OFFSET,
    build_portable_setup, validate_directory_object,
)
from exerepair.workflows.repair import apply_binary_patch, sha256
from tests.test_disc_repair import fixture

BASE, CODE, STATE = 0x400000, 0x50000000, 0x50010000


def call(rva, target):
    return rva, b"\xe8" + struct.pack("<i", target-rva-5)


def portable_spec():
    return PortableSetupProfile(
        key_check=call(0x4000, 0x8000),
        directory_queries=(call(0x5000, 0x8100), call(0x5100, 0x8100)),
        setup_query=call(0x5200, 0x8100),
        directory_object_rva=0x9000,
        assign_string=(0x3000, bytes.fromhex("558bec538b5d0c")),
        assign_text=(0x3200, bytes.fromhex("558bec578bf8")),
    )


def portable_fixture():
    original, profile = fixture()
    original = bytearray(original)
    struct.pack_into("<I", original, 0x98+0x38, 0x10000)
    struct.pack_into("<I", original, 0x178+8, 0xF000)
    original = bytes(original)
    return original, replace(
        profile, name="synthetic-portable", baseline_sha256=sha256(original),
        module_image_size=0x10000, region_ready_rva=0x6000,
        success_flag_rva=0xA000, caller_return_rva=0xA100, return_rva=0xA200,
        region_ready_bytes=bytes.fromhex("558bec"),
        region_patch_sites=((0x4500, bytes.fromhex("741290"), bytes.fromhex("eb1290")),),
        portable_setup=portable_spec(),
    )


def test_setup_plan_is_name_independent_and_preserves_standard_transaction():
    original, profile = portable_fixture()
    built = build_disc_repair(original, profile)
    renamed = build_disc_repair(original, replace(profile, name="another-label"))
    assert built.data == renamed.data
    assert apply_binary_patch(original, built.patch) == built.data
    assert built.report["runtime_launch_verified"] is False
    layout = built.report["helper_layout"]
    assert layout["portable_installation"] is True
    assert layout["portable_stub_offset"] == STUB_OFFSET
    assert layout["portable_directory_wstring_va"] == hex(BASE+0x9000)
    assert "no installation registry access" in built.report["changed_symbol"]
    assert "0x50b51" not in built.report["changed_symbol"]
    assert len(disc_helper(profile, CODE, STATE, BASE+0x1000)[0]) <= HELPER_CAPACITY


def test_plan_returns_exact_guards_and_bound_call_targets():
    spec = portable_spec()
    plan = build_portable_setup(spec, BASE, CODE, 0x10000)
    assert plan.guards == (
        spec.key_check, *spec.directory_queries, spec.setup_query,
        spec.assign_string, spec.assign_text,
    )
    assert plan.patches[0] == (*spec.key_check, bytes.fromhex("b001909090"))
    for site, offset in zip(plan.patches[1:], (0, 0, TEXT_OFFSET)):
        rva, expected, replacement = site
        assert len(expected) == len(replacement) == 5
        assert BASE+rva+5+struct.unpack("<i", replacement[1:])[0] == CODE+STUB_OFFSET+offset
    assert plan.code[LITERAL_OFFSET:] == "full\0".encode("utf-16-le")


@pytest.mark.parametrize("change", [
    {"directory_queries": ()},
    {"key_check": (0x4000, b"\xe8")},
    {"setup_query": (0x5200, b"\xe9\0\0\0\0")},
    {"setup_query": call(0x5000, 0x8100)},
    {"setup_query": call(0x5002, 0x8100)},
    {"assign_string": (0x3000, b"")},
    {"assign_text": (0xFFFF, b"\x55\x8b\xec")},
    {"directory_object_rva": 0x9001},
    {"directory_object_rva": -4},
    {"directory_object_rva": 0xFFFFFFFC},
    {"installed_value": ""},
    {"installed_value": "full\0other"},
    {"installed_value": "\ud800"},
    {"installed_value": "a" * 1000},
])
def test_plan_rejects_incomplete_overlapping_or_unbounded_configuration(change):
    with pytest.raises(RecoveryError):
        build_portable_setup(replace(portable_spec(), **change), BASE, CODE, 0x10000)


@pytest.mark.parametrize("base,code", [
    (-1, CODE), (0xFFFFF000, CODE), (BASE, -1), (BASE, 0xFFFFF001), (BASE, 0x90000000),
])
def test_plan_rejects_address_or_rel32_overflow(base, code):
    with pytest.raises(RecoveryError):
        build_portable_setup(portable_spec(), base, code, 0x10000)


def test_wrapper_image_bounds_and_existing_patches_are_checked():
    original, profile = portable_fixture()
    assert profile.portable_setup is not None
    spec = replace(profile.portable_setup, directory_object_rva=0xFFF0)
    with pytest.raises(RecoveryError):
        validate_directory_object(spec, 0x10000)
    with pytest.raises(RecoveryError):
        build_disc_repair(original, replace(profile, portable_setup=spec))
    with pytest.raises(RecoveryError, match="重叠"):
        disc_helper(replace(profile, setup_patch_sites=((0x4002, b"\0", b"\x90"),)),
                    CODE, STATE, BASE+0x1000)
    with pytest.raises(RecoveryError, match="独立"):
        disc_helper(replace(profile, region_patch_sites=()), CODE, STATE, BASE+0x1000)


def _verify_machine(mode):
    import unicorn as u
    from unicorn import x86_const as r

    _, profile = portable_fixture()
    spec = profile.portable_setup
    code, state, layout = disc_helper(profile, CODE, STATE, BASE+0x1000)
    uc = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    stack, api, stop = 0x60000000, 0x70000000, 0x70000800
    for address, size in [(BASE, 0x10000), (CODE, 0x1000), (STATE, 0x1000),
                          (stack, 0x4000), (api, 0x1000)]:
        uc.mem_map(address, size)
    uc.mem_write(CODE, code)
    uc.mem_write(STATE, state)

    def put(address, *values):
        uc.mem_write(address, struct.pack("<" + "I"*len(values), *values))

    def read(address):
        return struct.unpack("<I", uc.mem_read(address, 4))[0]

    sp, destination = stack+0x1000, stack+0x2000
    put(sp, stop, stack+0x2100)
    registers = {r.UC_X86_REG_EBX: 0x1111, r.UC_X86_REG_ESI: 0x2222,
                 r.UC_X86_REG_EDI: 0x3333, r.UC_X86_REG_EBP: 0x4444}
    for register, value in registers.items():
        uc.reg_write(register, value)
    uc.reg_write(r.UC_X86_REG_ESP, sp)
    uc.reg_write(r.UC_X86_REG_ECX, destination)
    calls = []

    def stdcall(count, result):
        esp = uc.reg_read(r.UC_X86_REG_ESP)
        uc.reg_write(r.UC_X86_REG_EIP, read(esp))
        uc.reg_write(r.UC_X86_REG_ESP, esp+4*(count+1))
        uc.reg_write(r.UC_X86_REG_EAX, result)

    def dispatch(uc, address, size, _):
        esp = uc.reg_read(r.UC_X86_REG_ESP)
        if address == BASE+spec.assign_string[0]:
            assert uc.reg_read(r.UC_X86_REG_ECX) == destination
            assert uc.reg_read(r.UC_X86_REG_EAX) == 0xFFFFFFFF
            assert read(esp+4) == BASE+spec.directory_object_rva
            assert read(esp+8) == 0
            # Copy a synthetic UTF-16 object with non-ACP and surrogate chars.
            uc.mem_write(destination, bytes(uc.mem_read(BASE+spec.directory_object_rva, 24)))
            calls.append("copy_string")
            stdcall(2, destination)
        elif address == BASE+spec.assign_text[0]:
            assert uc.reg_read(r.UC_X86_REG_ESI) == destination
            units = read(esp+4)
            raw = bytes(uc.mem_read(uc.reg_read(r.UC_X86_REG_EAX), 2*(units+1)))
            assert raw == "full\0".encode("utf-16-le")
            uc.mem_write(destination, raw)
            calls.append("copy_text")
            stdcall(1, destination)
        elif address == api:
            calls.append("query")
            ready = BASE+profile.region_ready_rva
            put(read(esp+8), ready & ~0xFFF, BASE, 0x40, 0x1000, 0x1000, 0x20, 0x20000)
            stdcall(3, 28)
        elif address == api+0x10:
            calls.append("sleep")
            # Exercise the real final poll iteration without 60,000 API calls.
            uc.reg_write(r.UC_X86_REG_EDI, 1)
            stdcall(1, 0)
        elif address == api+0x20:
            calls.append("protect")
            put(read(esp+16), 0x20)
            stdcall(4, 0 if mode == "protect-denied" else 1)
        elif address == api+0x30:
            calls.append("flush")
            stdcall(3, 1)

    uc.hook_add(u.UC_HOOK_CODE, dispatch)
    if mode in ("path", "type", "key"):
        raw = "便携目录\\テスト\\🧪\0".encode("utf-16-le")
        uc.mem_write(stack+0x3000, raw)
        put(BASE+spec.directory_object_rva, stack+0x3000, 0, 0, 0, len(raw)//2-1, 64)
        if mode == "key":
            uc.mem_write(api+0x200, bytes.fromhex("b001909090c3"))
            start = api+0x200
        else:
            start = CODE+STUB_OFFSET+(TEXT_OFFSET if mode == "type" else 0)
        uc.emu_start(start, stop, count=1000)
        assert uc.reg_read(r.UC_X86_REG_EAX) & 0xFF == 1
        assert uc.reg_read(r.UC_X86_REG_ESP) == sp+4
        assert read(sp+4) == stack+0x2100
        for register, value in registers.items():
            assert uc.reg_read(register) == value
        if mode == "path":
            assert calls == ["copy_string"]
            assert bytes(uc.mem_read(read(destination), len(raw))) == raw
        elif mode == "type":
            assert calls == ["copy_text"]
        else:
            assert not calls
        return

    plan = build_portable_setup(spec, BASE, CODE, profile.module_image_size)
    patches = (*profile.region_patch_sites, *plan.patches)
    for rva, expected in (*plan.guards, (profile.region_ready_rva, profile.region_ready_bytes)):
        uc.mem_write(BASE+rva, expected)
    for rva, expected, _ in patches:
        uc.mem_write(BASE+rva, expected)
    if mode == "timeout":
        uc.mem_write(BASE+profile.region_ready_rva, b"\0")
    elif mode.startswith("guard-"):
        index, offset = map(int, mode.split("-")[1:])
        rva, expected = plan.guards[index]
        uc.mem_write(BASE+rva+offset, bytes([expected[offset] ^ 1]))
    before = [bytes(uc.mem_read(BASE+rva, len(data))) for rva, data, _ in patches]
    put(STATE+0x24, api)
    put(STATE+0x30, api+0x10)
    put(STATE+0x04, api+0x20)
    put(STATE+0x20, api+0x30)
    uc.emu_start(CODE+layout["region_worker_offset"], stop, count=10000)
    assert uc.reg_read(r.UC_X86_REG_ESP) == sp+8
    assert uc.reg_read(r.UC_X86_REG_EAX) == 0
    for register, value in registers.items():
        assert uc.reg_read(register) == value
    if mode == "success":
        assert read(STATE+0x38) == 1
        for rva, _, replacement in patches:
            assert bytes(uc.mem_read(BASE+rva, len(replacement))) == replacement
        assert "flush" in calls
    else:
        assert read(STATE+0x38) == 0 and "flush" not in calls
        for (rva, expected, _), saved in zip(patches, before):
            assert bytes(uc.mem_read(BASE+rva, len(expected))) == saved
        if mode != "protect-denied":
            assert "protect" not in calls and "sleep" in calls


@pytest.mark.parametrize("group", ["abi", "guards", "worker"])
def test_generated_machine_code_abi_guards_and_bounded_worker(group):
    if importlib.util.find_spec("unicorn") is None:
        pytest.skip("optional Unicorn verifier not installed")
    guards = build_portable_setup(portable_spec(), BASE, CODE, 0x10000).guards
    cases = {
        "abi": ["path", "type", "key"],
        "guards": [f"guard-{i}-{j}" for i, (_, raw) in enumerate(guards) for j in range(len(raw))],
        "worker": ["success", "timeout", "protect-denied"],
    }[group]
    result = subprocess.run([
        sys.executable, "-B", "-c",
        "from tests.test_portable_setup import _verify_machine; "
        f"[_verify_machine(mode) for mode in {cases!r}]",
    ], capture_output=True, timeout=30, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert not result.stderr, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("value", ["完了", "🧪", "a"*128])
def test_installed_value_is_sized_in_utf16_code_units(value):
    spec = replace(portable_spec(), installed_value=value)
    plan = build_portable_setup(spec, BASE, CODE, 0x10000)
    literal = (value+"\0").encode("utf-16-le")
    assert plan.code[LITERAL_OFFSET:] == literal
    units = len(literal)//2-1
    push = b"\x6a"+bytes([units]) if units < 128 else b"\x68"+struct.pack("<I", units)
    assert plan.code[TEXT_OFFSET+8:TEXT_OFFSET+8+len(push)] == push


def test_publication_layout_remains_machine_readable():
    original, profile = portable_fixture()
    report = build_disc_repair(original, profile).report
    assert json.loads(json.dumps(report)) == report
    assert Path("TARGET.exe").name not in report["changed_symbol"]
