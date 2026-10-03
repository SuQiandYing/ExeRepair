from dataclasses import replace
import importlib.util
import json
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from exerepair.application import recovery
from exerepair.application.recovery import RepairService
from exerepair.domain.recovery import RecoveryError
from exerepair.workflows.native_repair import (
    _retire_dispatch_relocation, build_native_repair, native_trampoline,
)
from exerepair.workflows.profiles import EXHIBIT_DMM, EXHIBIT_DMM_TP02
from exerepair.workflows.repair import BuiltRepair, sha256
from tests.helpers import make_pe


def _verify_native_guard(mismatch, target="tp01"):
    import unicorn
    from unicorn import x86_const as r

    profile = EXHIBIT_DMM_TP02 if target == "tp02" else EXHIBIT_DMM
    base, helper_rva = 0x400000, 0x970000
    helper = base+helper_rva
    continuation = base+profile.engine_base_delta+profile.dispatch_rva+5
    global_address = base+profile.engine_base_delta+profile.dispatch_global_rva
    guard_address = base+profile.guard_rva
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    for address in {helper & ~0xFFF, continuation & ~0xFFF, global_address & ~0xFFF,
                    guard_address & ~0xFFF, 0x900000}:
        emu.mem_map(address, 0x1000)
    data = bytearray(profile.guard_bytes)
    if isinstance(mismatch, int):
        data[mismatch] ^= 1
    elif mismatch == "already-patched":
        data[5:7] = b"\x90\x90"
    elif mismatch == "not-unpacked":
        data[:] = bytes(len(data))
    emu.mem_write(guard_address, bytes(data))
    emu.mem_write(global_address, struct.pack("<I", 0x12345678))
    emu.mem_write(helper, native_trampoline(profile, base, helper_rva))
    registers = {
        r.UC_X86_REG_EAX:0x11111111, r.UC_X86_REG_EBX:0x22222222,
        r.UC_X86_REG_ECX:0x33333333, r.UC_X86_REG_EDX:0x44444444,
        r.UC_X86_REG_ESI:0x55555555, r.UC_X86_REG_EDI:0x66666666,
        r.UC_X86_REG_EBP:0x77777777, r.UC_X86_REG_ESP:0x900800,
        r.UC_X86_REG_EFLAGS:0x246,
    }
    for register, value in registers.items():
        emu.reg_write(register, value)
    emu.emu_start(helper, continuation, count=100)
    expected = bytearray(data)
    if mismatch is None:
        expected[5:7] = b"\x90\x90"
    assert bytes(emu.mem_read(guard_address,10)) == expected
    assert emu.reg_read(r.UC_X86_REG_EAX) == 0x12345678  # displaced MOV is replayed
    for register, value in registers.items():
        if register != r.UC_X86_REG_EAX:
            assert emu.reg_read(register) == value
    assert emu.reg_read(r.UC_X86_REG_EIP) == continuation


@pytest.mark.parametrize("mismatch", [None, 0, 4, 5, 9, "already-patched", "not-unpacked"])
@pytest.mark.parametrize("target", ["tp01", "tp02"])
def test_native_trampoline_exact_guard_and_register_flag_preservation(mismatch, target):
    if importlib.util.find_spec("unicorn") is None:
        pytest.skip("optional Unicorn verifier not installed")
    # The native backend uses handled SEH probes on Windows. Keep these outside
    # pytest's fatal-signal handler, and still fail on any real child error.
    result = subprocess.run([
        sys.executable, "-c",
        f"from tests.test_native_repair import _verify_native_guard; "
        f"_verify_native_guard({mismatch!r}, {target!r})",
    ],capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert not result.stderr, result.stderr.decode(errors="replace")


def test_trampoline_rejects_unbound_call_shape():
    with pytest.raises(RecoveryError, match="保护字节"):
        native_trampoline(replace(EXHIBIT_DMM, guard_bytes=b"\0"*10),0x400000,0x964000)


def relocation_fixture():
    data = bytearray(1024)
    struct.pack_into("<I",data,0x3C,0x80)
    struct.pack_into("<I",data,0x80+24+96+5*8,0x300)
    struct.pack_into("<IIHH",data,0x300,0x133000,12,0x3AFF,0)
    profile = replace(EXHIBIT_DMM, relocation_offset=0x308)
    return data, SimpleNamespace(rva_to_offset=lambda rva:rva), profile


def test_retired_highlow_relocation_is_checked_inside_its_block():
    data, pe, profile = relocation_fixture()
    _retire_dispatch_relocation(data,pe,profile)
    assert struct.unpack_from("<H",data,0x308)[0] == 0
    assert struct.unpack_from("<II",data,0x300) == (0x133000,12)


@pytest.mark.parametrize("damage", ["type","page","range","alignment"])
def test_wrong_relocation_is_not_silently_retired(damage):
    data, pe, profile = relocation_fixture()
    if damage == "type":
        struct.pack_into("<H",data,0x308,0x2AFF)
    elif damage == "page":
        struct.pack_into("<I",data,0x300,0x134000)
    elif damage == "range":
        struct.pack_into("<I",data,0x304,10000)
    else:
        profile = replace(profile, relocation_offset=0x309)
    with pytest.raises(RecoveryError):
        _retire_dispatch_relocation(data,pe,profile)


def test_native_builder_rejects_other_build_without_loading_compressor():
    called = []
    with pytest.raises(RecoveryError, match="身份"):
        build_native_repair(b"another-build",EXHIBIT_DMM,lambda data:called.append(data))
    assert not called


@pytest.mark.parametrize("damage", ["base","aslr","not-writable"])
def test_native_builder_checks_pe_constraints_before_engine_processing(damage):
    data = make_pe(32)
    optional = struct.unpack_from("<I",data,0x3C)[0]+24
    struct.pack_into("<I",data,optional+0x1C,0x400000)
    struct.pack_into("<II",data,optional+0x20,0x1000,0x200)
    struct.pack_into("<II",data,optional+0x38,0x2000,0x200)
    if damage == "base":
        struct.pack_into("<I",data,optional+0x1C,0x500000)
    elif damage == "aslr":
        struct.pack_into("<H",data,optional+0x46,0x40)
    original = bytes(data)
    profile = replace(EXHIBIT_DMM,baseline_sha256=sha256(original),
                      baseline_size=len(original),guard_rva=0x1010,call_rva=0x1015)
    with pytest.raises(RecoveryError):
        build_native_repair(original,profile,lambda _:pytest.fail("compressor was called"))


def test_native_service_uses_static_branch_and_common_transaction(tmp_path,monkeypatch):
    original = b"native-build"
    profile = replace(EXHIBIT_DMM,baseline_sha256=sha256(original),baseline_size=len(original))
    source, output = tmp_path/"original.exe", tmp_path/"output.exe"
    source.write_bytes(original)
    monkeypatch.setattr(recovery,"identify_profile",lambda _:profile)
    monkeypatch.setattr(recovery.PEImage,"parse",lambda _:SimpleNamespace(
        entry_rva=1,image_base=0x400000,size_of_image=0x2000,sections=(1,)))
    calls = []
    modified = original+b"MODIFIED"

    def build(data,selected,compressor):
        calls.append((data,selected,compressor))
        return BuiltRepair(modified,{"modified_sha256":sha256(modified)},
                           {"runtime_launch_verified":False,"key_search_performed":False})

    monkeypatch.setattr(recovery,"build_native_repair",build)
    def compressor(data):
        return data
    service = RepairService(compressor=compressor)
    result = service.repair(source,output,backend="cpu",search_count=0)
    assert calls == [(original,profile,compressor)]
    assert source.read_bytes() == original
    assert output.read_bytes() == modified
    assert result.recovered_payload_count == 0
    verification = json.loads(result.verification_path.read_text())
    assert verification["recovered_manifest"] is None
    assert verification["key_search_performed"] is False
    assert verification["runtime_launch_verified"] is False
    assert result.rollback_path.read_text().startswith("#!/bin/sh\n")
    with pytest.raises(RecoveryError,match="不使用恢复清单"):
        service.repair(source,tmp_path/"another.exe",manifest=tmp_path/"missing.json")


def test_cli_native_inspection_does_not_advertise_payload_search(tmp_path,monkeypatch,capsys):
    from exerepair import cli
    source = tmp_path/"game.exe"
    source.write_bytes(make_pe(32))

    class Service:
        def inspect(self, _):
            return SimpleNamespace(profile=EXHIBIT_DMM)

        def repair(self, *args, **kwargs):
            pytest.fail("inspection must not repair or spawn")

    monkeypatch.setattr(cli,"RepairService",Service)
    assert cli.main(["--inspect",str(source)]) == 0
    output = capsys.readouterr().out
    assert "原生 executeAPI 调用" in output
    assert "不捕获、不搜索密钥" in output
    assert "载荷数量" not in output


def test_gui_native_inspection_has_correct_workflow_and_method(tmp_path):
    from exerepair.domain.recovery import RepairInspection
    from exerepair.ui.viewmodel import ConsoleController, WorkflowKind
    source = tmp_path/"game.exe"
    source.write_bytes(make_pe(32))

    class Service:
        def inspect(self, path):
            return RepairInspection(path,EXHIBIT_DMM,1,0x400000,0x2000,7)

    controller = ConsoleController(repair_service=Service())
    controller.begin_load(source)
    state = controller.load(source)
    assert state.workflow is WorkflowKind.REPAIR and state.can_act
    assert "无需 Frida/GPU" in state.status_detail
    rows = dict(row.values for row in state.rows)
    assert rows["原生调用"] == "RVA 0x183bb"
    assert rows["激活值"] == "不读取、不搜索、不写入"
