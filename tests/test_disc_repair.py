"""Synthetic fixtures only; real runtime evidence is kept outside the package."""
from dataclasses import replace
import importlib.util
import json
import os
import struct
import subprocess
import sys

import pytest

from exerepair.application import recovery
from exerepair.application.recovery import RepairService
from exerepair.domain.recovery import DiscCheckProfile, RecoveryError
from exerepair.formats.enigma import PEImage
from exerepair.workflows import profiles
from exerepair.workflows.disc_repair import build_disc_repair, disc_helper
from exerepair.workflows.profiles import DISC_CHECK_X86_V1
from exerepair.workflows.repair import apply_binary_patch, sha256
from tests.helpers import make_pe


def fixture():
    data = make_pe(32)
    optional = 0x98
    struct.pack_into("<I",data,optional+0x1C,0x400000)
    struct.pack_into("<I",data,optional+0x10,0x1000)
    struct.pack_into("<II",data,optional+0x20,0x1000,0x200)
    # Leave 80 contiguous bytes for two new section headers.
    data[0x200:0x200] = bytes(0x200)
    struct.pack_into("<II",data,optional+0x38,0x2000,0x400)
    struct.pack_into("<I",data,0x178+20,0x400)
    data[0x400:0x406] = b"\x55\x8b\xec\x33\xc0\xc3"
    original = bytes(data)
    profile = replace(DISC_CHECK_X86_V1,name="synthetic-disc",
                      baseline_sha256=sha256(original),baseline_size=len(original),
                      entry_rva=0x1000,entry_bytes=original[0x400:0x406],
                      registry_open_slot_rva=None,
                      registry_query_slot_rva=None,
                      registry_key_prefix=b"",
                      registry_value_names=(),
                      registry_ready_rva=None,
                      registry_ready_bytes=b"")
    return original, profile


def test_builder_preserves_original_sections_and_replays_standard_diff():
    original, profile = fixture()
    built = build_disc_repair(original,profile)
    pe = PEImage.parse(built.data)
    assert [s.name for s in pe.sections] == [".text",".repair",".rstate"]
    assert pe.sections[-2].characteristics == 0x60000020
    assert pe.sections[-1].characteristics == 0xC0000040
    assert built.data[0x400:len(original)] == original[0x400:]
    assert apply_binary_patch(original,built.patch) == built.data
    assert built.report["runtime_launch_verified"] is False
    assert built.report["original_packed_sections_unchanged"] is True
    assert built.report["new_rwx_sections"] is False
    assert built.report["helper_layout"]["hook_offset"] == 0x400


@pytest.mark.parametrize("damage",[
    "hash","size","base","aslr","entry","slot","signature","alignment","image","nonexecute",
])
def test_builder_rejects_unverified_identity_or_structure(damage):
    original, profile = fixture()
    data = bytearray(original)
    if damage == "hash":
        profile = replace(profile,baseline_sha256="0"*64)
    elif damage == "size":
        profile = replace(profile,baseline_size=len(data)+1)
    elif damage == "base":
        struct.pack_into("<I",data,0x98+0x1C,0x500000)
    elif damage == "aslr":
        struct.pack_into("<H",data,0x98+0x46,0x40)
    elif damage == "entry":
        data[0x400] ^= 1
    elif damage == "slot":
        data[0x178+40] = 1
    elif damage == "signature":
        struct.pack_into("<II",data,0x98+96+4*8,0x700,32)
    elif damage == "alignment":
        struct.pack_into("<I",data,0x98+0x24,0x300)
    elif damage == "image":
        struct.pack_into("<I",data,0x98+0x38,0x1000)
    else:
        struct.pack_into("<I",data,0x178+36,0x40000040)
    if damage not in ("hash","size"):
        profile = replace(profile,baseline_sha256=sha256(data),baseline_size=len(data))
    with pytest.raises(RecoveryError):
        build_disc_repair(bytes(data),profile)


@pytest.mark.parametrize("change",[
    {"return_guard":b"\0"*16},
    {"caller_guard":b"\x90"},
    {"return_rva":-1},
    {"success_flag_rva":0xFFFFFFFC},
    {"success_flag_rva":DISC_CHECK_X86_V1.return_rva},
])
def test_helper_rejects_unsafe_profile(change):
    with pytest.raises(RecoveryError):
        disc_helper(replace(DISC_CHECK_X86_V1,**change),0x500000,0x501000,0x401000)


def test_v1_registry_compatibility_is_process_local_and_layout_is_reported():
    code,state,layout = disc_helper(
        DISC_CHECK_X86_V1,0x50000000,0x50010000,0x401ACFD3,
    )
    assert len(state) == 0x400
    assert layout["registry_slots"] == {
        "open":"0x37b038","query":"0x37b004",
    }
    assert layout["registry_worker_offset"] == 0xB00
    assert layout["registry_stub_offsets"] == {"open":0x800,"query":0x980}
    assert state[0x100:0x100+21] == b"GetCurrentDirectoryA\0"
    assert struct.unpack_from("<I",state,0x148)[0] == 0x52454731
    assert len(code) <= 0x1000


def test_registry_compatibility_rejects_partial_configuration():
    with pytest.raises(RecoveryError):
        disc_helper(
            replace(DISC_CHECK_X86_V1,registry_query_slot_rva=None),
            0x50000000,0x50010000,0x401ACFD3,
        )


def test_service_uses_common_publication_without_optional_components(tmp_path,monkeypatch):
    original, profile = fixture()
    source, output = tmp_path/"arbitrary-name.exe",tmp_path/"result.exe"
    source.write_bytes(original)
    monkeypatch.setattr(profiles,"PROFILES",(profile,))
    monkeypatch.setattr(recovery,"AplibCompressor",lambda *_:pytest.fail("compressor loaded"))
    monkeypatch.setattr(recovery,"discover_native_runtime",lambda *_a,**_k:pytest.fail("capture"))
    result = RepairService().repair(source,output)
    assert source.read_bytes() == original
    assert result.original_unchanged and result.recovered_payload_count == 0
    report = json.loads(result.verification_path.read_text())
    assert report["strategy"] == "guarded-disc-check"
    assert report["recovered_manifest"] is None
    assert report["runtime_launch_verified"] is False
    assert output.with_name(output.name+".baseline.exe").read_bytes() == original
    assert result.rollback_path.read_text().startswith("#!/bin/sh\n")
    assert apply_binary_patch(original,json.loads(result.diff_path.read_text())) == output.read_bytes()
    # The service remains idempotent for an already matching transaction.
    assert RepairService().repair(source,output).output_sha256 == result.output_sha256
    output.write_bytes(b"user content")
    with pytest.raises(RecoveryError,match="--force"):
        RepairService().repair(source,output)
    assert output.read_bytes() == b"user content"
    RepairService().repair(source,output,overwrite=True)
    with pytest.raises(RecoveryError,match="不使用恢复清单"):
        RepairService().repair(source,tmp_path/"other.exe",manifest=tmp_path/"unused.json")
    with pytest.raises(RecoveryError,match="副本"):
        RepairService().repair(source,source)
    alias = tmp_path/"hardlink.exe"
    os.link(source,alias)
    with pytest.raises(RecoveryError,match="硬链接"):
        RepairService().repair(source,alias)


def test_disc_profile_is_public_and_identity_not_filename_controls_inspection(tmp_path,monkeypatch):
    from exerepair.api import DiscCheckProfile as PublicProfile
    original, profile = fixture()
    assert PublicProfile is DiscCheckProfile
    monkeypatch.setattr(profiles,"PROFILES",(profile,))
    source = tmp_path/"renamed.exe"
    source.write_bytes(original)
    assert RepairService().inspect(source).profile == profile
    source.write_bytes(original+b"x")
    with pytest.raises(RecoveryError):
        RepairService().inspect(source)


def test_cli_and_gui_disc_route(tmp_path,monkeypatch,capsys):
    from exerepair import cli
    from exerepair.ui.viewmodel import ConsoleController,WorkflowKind
    original, profile = fixture()
    monkeypatch.setattr(profiles,"PROFILES",(profile,))
    source = tmp_path/"input.exe"
    source.write_bytes(original)
    assert cli.main(["--inspect",str(source)]) == 0
    printed = capsys.readouterr().out
    assert "光盘检查兼容" in printed and "不依赖压缩器" in printed
    assert "载荷数量" not in printed
    controller = ConsoleController()
    controller.begin_load(source)
    state = controller.load(source)
    assert state.can_act and state.workflow is WorkflowKind.REPAIR
    rows = dict(row.values for row in state.rows)
    assert rows["光盘检查"] == f"模块 RVA {profile.return_rva:#x}"
    assert ".rstate" in rows["修复方法"]
    assert "无需 Frida/GPU 或压缩器" in state.status_detail


def _verify_machine(mode):
    """Emulate both entry and one-shot callback with synthetic Windows APIs."""
    import unicorn
    from unicorn import x86_const as r

    profile = replace(
        DISC_CHECK_X86_V1,
        registry_open_slot_rva=None,
        registry_query_slot_rva=None,
        registry_key_prefix=b"",
        registry_value_names=(),
        registry_ready_rva=None,
        registry_ready_bytes=b"",
    )
    code_va,state_va,entry,stack,kernel = 0x50000000,0x50010000,0x400000,0x60000000,0x71000000
    module = 0x17000000 if mode == "relocated" else 0x11000000
    code,state,layout = disc_helper(profile,code_va,state_va,entry)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    for address,size in ((0,0x10000),(entry,0x1000),(code_va,0x1000),(state_va,0x1000),
                         (stack,0x2000),(kernel,0x10000),(module,0x580000)):
        uc.mem_map(address,size)
    def put(address,*values):
        uc.mem_write(address,struct.pack("<"+"I"*len(values),*values))
    def read(address):
        return struct.unpack("<I",uc.mem_read(address,4))[0]
    uc.mem_write(code_va,code)
    uc.mem_write(state_va,state)
    # PEB, loader circular list, first unrelated module and then kernel32.
    put(0x30,0x1000)
    put(0x100C,0x2000)
    put(0x2014,0x3000)
    put(0x3000,0x4000)
    put(0x4000,0x2014)
    uc.mem_write(0x4024,struct.pack("<H",24))
    put(0x4028,0x5000)
    put(0x4010,kernel)
    uc.mem_write(0x5000,("KERNEL32.DLL" if mode != "missing-kernel" else "XXXXXXXX.DLL").encode("utf-16le"))
    put(kernel+0x3C,0x80)
    put(kernel+0x80+0x78,0x1000,0x300)
    put(kernel+0x1018,1,0x2000,0x2100,0x2200)
    put(kernel+0x2000,0x8000 if mode != "forwarder" else 0x1100)
    put(kernel+0x2100,0x2300)
    uc.mem_write(kernel+0x2200,b"\0\0")
    uc.mem_write(kernel+0x2300,b"GetProcAddress\0")
    gp,vp,flush,query,drive = [kernel+x for x in (0x8000,0x8100,0x8200,0x8300,0x8400)]
    api_stub,api_slot = kernel+0x9000,kernel+0x9100
    uc.mem_write(api_stub,b"\xff\x25"+struct.pack("<I",api_slot))
    if mode == "unknown-api":
        uc.mem_write(api_stub,b"\xc3")
    put(api_slot,drive)
    for address in (gp,vp,flush,query,drive):
        uc.mem_write(address,b"\xc3")
    uc.mem_write(module,b"MZ")
    put(module+0x3C,0x80)
    put(module+0x80,0x4550)
    uc.mem_write(module+0x84,struct.pack("<H",0x14C))
    uc.mem_write(module+0x98,struct.pack("<H",0x10B))
    put(module+0xD0,profile.module_image_size)
    caller = bytearray(profile.caller_guard)
    epilogue = bytearray(profile.return_guard)
    if mode.startswith("caller-"):
        caller[int(mode.split("-")[1])] ^= 1
    if mode.startswith("return-"):
        epilogue[int(mode.split("-")[1])] ^= 1
    uc.mem_write(module+profile.caller_return_rva,bytes(caller))
    uc.mem_write(module+profile.return_rva,bytes(epilogue))
    if mode == "wrong-size":
        put(module+0xD0,0x30000)
    if mode == "wrong-machine":
        uc.mem_write(module+0x84,b"\x64\x86")
    calls = []
    def stdcall(count,value):
        sp = uc.reg_read(r.UC_X86_REG_ESP)
        return_address = read(sp)
        uc.reg_write(r.UC_X86_REG_ESP,sp+4+count*4)
        uc.reg_write(r.UC_X86_REG_EAX,value)
        uc.reg_write(r.UC_X86_REG_ECX,0xAAAAAAAA)
        uc.reg_write(r.UC_X86_REG_EDX,0xBBBBBBBB)
        uc.reg_write(r.UC_X86_REG_EIP,return_address)
    def api(_uc,address,_size,_data):
        sp = uc.reg_read(r.UC_X86_REG_ESP)
        if address == gp:
            pointer = read(sp+8)
            name = bytearray()
            while uc.mem_read(pointer+len(name),1) != b"\0":
                name.extend(uc.mem_read(pointer+len(name),1))
            name = name.decode()
            result = {"VirtualProtect":vp,"FlushInstructionCache":flush,
                      "VirtualQuery":query,"GetDriveTypeA":api_stub}[name]
            stdcall(2,0 if mode == "missing-export" and name == "VirtualQuery" else result)
        elif address == vp:
            target,length,protection,out = [read(sp+i) for i in (4,8,12,16)]
            calls.append(("protect",target,length,protection))
            failed = ((mode == "deny-install" and target == api_slot) or
                      (mode == "deny-code" and target == module+profile.return_rva) or
                      (mode == "deny-flag" and target == module+profile.success_flag_rva))
            if not failed:
                put(out,0x20 if target == module+profile.return_rva else 4)
            stdcall(4,0 if failed else 1)
        elif address == query:
            target = read(sp+4)
            out = read(sp+8)
            put(out,target & ~0xFFF,module,4,0x1000,0x1000,4,0x20000)
            if mode == "inaccessible":
                put(out+0x14,0x101)
            if mode == "unreadable-return" and target == module+profile.return_rva:
                put(out+0x14,1)
            if mode == "short-region" and target == module+profile.return_rva:
                put(out+0x0C,profile.return_rva & 0xFFF)
            if mode == "wrong-allocation":
                put(out+4,module+0x1000)
            stdcall(3,0 if mode == "query-failed" else 28)
        elif address == flush:
            calls.append(("flush",read(sp+4),read(sp+8),read(sp+12)))
            stdcall(3,1)
    uc.hook_add(unicorn.UC_HOOK_CODE,api)
    registers = {
        r.UC_X86_REG_EAX:0x11111111,r.UC_X86_REG_EBX:0x22222222,
        r.UC_X86_REG_ECX:0x33333333,r.UC_X86_REG_EDX:0x44444444,
        r.UC_X86_REG_ESI:0x55555555,r.UC_X86_REG_EDI:0x66666666,
        r.UC_X86_REG_EBP:0x77777777,r.UC_X86_REG_ESP:stack+0x1000,
        r.UC_X86_REG_EFLAGS:0x646,
    }
    def reset():
        for register,value in registers.items():
            uc.reg_write(register,value)
    def unchanged():
        for register,value in registers.items():
            assert uc.reg_read(register) == value, (mode,register,hex(uc.reg_read(register)),hex(value))
    reset()
    uc.emu_start(code_va,entry,count=10000)
    assert uc.reg_read(r.UC_X86_REG_EIP) == entry
    unchanged()
    no_install = mode in ("missing-kernel","forwarder","unknown-api","missing-export","deny-install")
    if no_install:
        assert read(api_slot) == drive
        return
    assert read(api_slot) == code_va+layout["hook_offset"]
    if mode == "foreign-slot":
        put(api_slot,kernel+0x8500)
    reset()
    put(stack+0x1000,module+profile.caller_return_rva+(1 if mode == "unrelated-caller" else 0))
    uc.emu_start(code_va+layout["hook_offset"],drive,count=10000)
    assert uc.reg_read(r.UC_X86_REG_EIP) == drive
    unchanged()
    patched = mode in ("match","relocated","foreign-slot")
    expected = b"\x33\xc0\x40"+bytes(epilogue[3:]) if patched else bytes(epilogue)
    assert bytes(uc.mem_read(module+profile.return_rva,len(epilogue))) == expected
    assert read(module+profile.success_flag_rva) == int(patched)
    assert read(state_va+28) == int(patched)
    assert bool([c for c in calls if c[0] == "flush"]) == patched
    if patched:
        assert read(api_slot) == (kernel+0x8500 if mode == "foreign-slot" else drive)
        before = list(calls)
        reset()
        uc.emu_start(code_va+layout["hook_offset"],drive,count=10000)
        unchanged()
        assert calls == before  # one shot, including no repeat VirtualProtect


@pytest.mark.parametrize("group",["startup","guards","success"])
def test_machine_code_entry_and_callback_preserve_abi_and_fail_closed(group):
    if importlib.util.find_spec("unicorn") is None:
        pytest.skip("optional Unicorn verifier not installed")
    cases = {
        "startup":["missing-kernel","forwarder","unknown-api","missing-export","deny-install"],
        "guards":["query-failed","inaccessible","wrong-allocation","wrong-size","wrong-machine",
                  "unrelated-caller","unreadable-return","short-region","deny-code","deny-flag"]+
                 [f"caller-{i}" for i in range(len(DISC_CHECK_X86_V1.caller_guard))]+
                 [f"return-{i}" for i in range(len(DISC_CHECK_X86_V1.return_guard))],
        "success":["match","relocated","foreign-slot"],
    }[group]
    result = subprocess.run([
        sys.executable,"-c","from tests.test_disc_repair import _verify_machine; "+
        f"[_verify_machine(mode) for mode in {cases!r}]",
    ],capture_output=True,timeout=45)
    assert result.returncode == 0,result.stderr.decode(errors="replace")
    assert not result.stderr,result.stderr.decode(errors="replace")
