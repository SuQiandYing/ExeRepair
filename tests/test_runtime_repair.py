from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zipfile
import zlib

import pytest

from exerepair.adapters.aplib import ARCHIVE_SHA256
from exerepair.adapters.runtime_capture import _capture_config
from exerepair.application import recovery
from exerepair.application.recovery import RepairService, load_payload_manifest, save_payload_manifest
from exerepair.domain.recovery import PayloadSpec, RecoveredPayload, RecoveryError, RepairProfile
from exerepair.formats.enigma import PEImage, bcj_transform
from exerepair.workflows.profiles import ENIGMA_PE32_1_31_DYNAMIC_BASE, identify_profile
from exerepair.workflows.repair import (
    BuiltRepair, apply_binary_patch, helper_and_data, patch_gate, sha256,
    validate_payloads,
)
from tests.helpers import make_pe


def fixture():
    original = make_pe(32)
    optional = struct.unpack_from("<I", original, 0x3C)[0] + 24
    struct.pack_into("<I", original, optional + 0x1C, 0x400000)
    struct.pack_into("<II", original, optional + 0x20, 0x1000, 0x200)
    struct.pack_into("<II", original, optional + 0x38, 0x2000, 0x200)
    original = bytes(original)
    pe = PEImage.parse(original)
    section = pe.sections[0]
    data = b"recovered-code\0"
    spec = PayloadSpec(section.virtual_address, section.raw_offset, len(data), 11,
                       zlib.crc32(data), sha256(data))
    profile = RepairProfile("synthetic", sha256(original), len(original), "", 0, 0, 0, (spec,))
    return original, profile, (RecoveredPayload(spec, data),)


def patch_fixture():
    original = b"abcdef"
    modified = b"abXYefTAIL"
    patch = {
        "format": "seep.binary-patch.v2",
        "baseline_sha256": sha256(original), "modified_sha256": sha256(modified),
        "length": len(original), "modified_length": len(modified),
        "edits": [
            {"offset": 2, "length": 2, "replacement_base64": base64.b64encode(b"XY").decode()},
            {"offset": 6, "length": 4, "mode": "append",
             "replacement_base64": base64.b64encode(b"TAIL").decode()},
        ],
    }
    return original, modified, patch


def gate_fixture(*, with_dialog=False):
    """Build a tiny decoded VM image for exact gate checks."""
    table_offset = 0x100
    predicate_offset = 0x200
    true_offset = 0x248
    dialog_offset = 0x290
    table_count = 4
    engine = bytearray(0x340)
    old_predicate = struct.pack(
        "<18I", 0x60, 0, 0, 0x8D, 0x28, 0, 0x202000, 0x184, 0x8F,
        0, 0, 0x2000, 0x123456, 0, 0, 0, 0x200000, 0,
    )
    true_record = struct.pack(
        "<18I", 0x52, 0, 0, 0x8C, 1, 0, 0x200800, 0, 0x8F,
        0, 0, 0x200800, 1, 0, 0, 0, 0x200000, 0,
    )
    engine[predicate_offset:predicate_offset + 72] = old_predicate
    engine[true_offset:true_offset + 72] = true_record
    struct.pack_into("<II", engine, table_offset + 4, predicate_offset, true_offset)
    if with_dialog:
        struct.pack_into("<I", engine, table_offset, dialog_offset)
        struct.pack_into("<I", engine, dialog_offset, 0x2C)
        struct.pack_into("<I", engine, dialog_offset + 28, 3)
    profile = RepairProfile(
        "synthetic-gate", sha256(bytes(engine)), len(engine), sha256(bytes(engine)),
        0, table_offset, table_count, (),
        dialog_index=0 if with_dialog else None,
        dialog_destination=3 if with_dialog else None,
        predicate_index=1, true_index=2,
        predicate_record_offset=predicate_offset,
        true_record_offset=true_offset,
        predicate_return_operand=0x123456,
    )
    return bytes(engine), profile


def test_patch_gate_supports_verified_no_dialog_build():
    engine, profile = gate_fixture()
    changed, edits = patch_gate(engine, profile)
    assert changed[profile.vm_table_offset + profile.predicate_index * 4:
                   profile.vm_table_offset + profile.predicate_index * 4 + 4] == struct.pack(
                       "<I", profile.true_record_offset
                   )
    assert any("retire sole-referenced" in row["symbol"] for row in edits)
    assert not any("JZ -> JMP" in row["symbol"] for row in edits)


def test_patch_gate_preserves_legacy_dialog_branch_when_configured():
    engine, profile = gate_fixture(with_dialog=True)
    _changed, edits = patch_gate(engine, profile)
    assert any("JZ -> JMP" in row["symbol"] for row in edits)


@pytest.mark.parametrize("damage", ["optional", "predicate-address", "truth-bytes", "duplicate"])
def test_patch_gate_rejects_inexact_gate_evidence(damage):
    engine, profile = gate_fixture()
    if damage == "optional":
        profile = replace(profile, dialog_index=None, dialog_destination=3)
    elif damage == "predicate-address":
        profile = replace(profile, predicate_record_offset=0x204)
    elif damage == "truth-bytes":
        broken = bytearray(engine)
        broken[profile.true_record_offset + 4] ^= 1
        engine = bytes(broken)
        profile = replace(profile, engine_sha256=sha256(engine))
    else:
        broken = bytearray(engine)
        struct.pack_into("<I", broken, profile.vm_table_offset + 12, profile.predicate_record_offset)
        engine = bytes(broken)
        profile = replace(profile, engine_sha256=sha256(engine))
    with pytest.raises(RecoveryError):
        patch_gate(engine, profile)


def test_build_repair_rejects_aslr_before_compression_for_legacy_profile():
    original = make_pe(32)
    optional = struct.unpack_from("<I", original, 0x3C)[0] + 24
    struct.pack_into("<I", original, optional + 0x1C, 0x400000)
    struct.pack_into("<II", original, optional + 0x20, 0x1000, 0x200)
    struct.pack_into("<II", original, optional + 0x38, 0x2000, 0x200)
    struct.pack_into("<H", original, optional + 0x46, 0x40)
    data = bytes(original)
    profile = RepairProfile(
        "legacy-aslr", sha256(data), len(data), "", 0, 0, 0, (),
    )
    with pytest.raises(RecoveryError, match="ASLR"):
        from exerepair.workflows.repair import build_repair
        build_repair(data, profile, (), lambda _: pytest.fail("compressor called"))


def test_capture_config_is_offset_only_and_exact_profile_gated():
    config = _capture_config(ENIGMA_PE32_1_31_DYNAMIC_BASE)
    assert config["engineBaseDelta"] == ENIGMA_PE32_1_31_DYNAMIC_BASE.engine_base_delta
    assert config["dispatchRVA"] == ENIGMA_PE32_1_31_DYNAMIC_BASE.dispatch_rva
    assert config["nativeTargetType"] == 0x90
    assert not any(isinstance(value, str) and (":" in value or "\\" in value)
                   for value in config.values())
    with pytest.raises(RecoveryError, match="尚无经过验证"):
        _capture_config(replace(ENIGMA_PE32_1_31_DYNAMIC_BASE, runtime_capture_supported=False))


@pytest.mark.parametrize("data", [
    b"", b"\xe8\0\0\0\0", b"A\xe8\xfe\xff\xff\xffZ\xe9\xff\xff\xff\xff",
    b"\xff\x25\x12\x34\x56\x78\xff\x25\xff\xff\xff\xff",
    bytes(range(256)) * 3,
])
def test_bcj_round_trip_and_no_input_mutation(data):
    before = bytes(data)
    assert bcj_transform(bcj_transform(data, encode=False), encode=True) == data
    assert data == before


def test_bcj_known_absolute_and_indirect_deltas():
    data = b"A\xe8" + struct.pack("<I", 100) + b"\xff\x25" + struct.pack("<I", 32)
    data += b"\xff\x25" + struct.pack("<I", 32)
    decoded = bcj_transform(data, encode=False)
    assert struct.unpack_from("<I", decoded, 2)[0] == 99
    assert struct.unpack_from("<I", decoded, 8)[0] == 32
    assert struct.unpack_from("<I", decoded, 14)[0] == 36


def test_patch_replay_preserves_baseline():
    original, modified, patch = patch_fixture()
    assert apply_binary_patch(original, patch) == modified
    assert original == b"abcdef"


@pytest.mark.parametrize("case", ["hash", "size", "overlap", "negative", "append", "length", "output"])
def test_patch_rejects_invalid_ranges_and_identities(case):
    original, _modified, patch = patch_fixture()
    if case == "hash":
        patch["baseline_sha256"] = "0" * 64
    elif case == "size":
        patch["length"] += 1
    elif case == "overlap":
        patch["edits"].insert(1, dict(patch["edits"][0]))
    elif case == "negative":
        patch["edits"][0]["offset"] = -1
    elif case == "append":
        patch["edits"][1]["offset"] -= 1
    elif case == "length":
        patch["edits"][0]["length"] += 1
    elif case == "output":
        patch["modified_sha256"] = "0" * 64
    with pytest.raises(RecoveryError):
        apply_binary_patch(original, patch)


def test_payload_manifest_recomputes_crc_and_hash(tmp_path):
    original, profile, payloads = fixture()
    path = save_payload_manifest(tmp_path, original, profile, payloads)
    assert load_payload_manifest(path, original, profile) == payloads
    data = json.loads(path.read_text())
    assert "destination_rva" not in data["payloads"][0]
    assert "key_prefix" not in path.read_text()
    assert "component" not in data
    (tmp_path / data["payloads"][0]["path"]).write_bytes(b"broken")
    with pytest.raises(RecoveryError):
        load_payload_manifest(path, original, profile)


def test_legacy_enabled_field_is_not_used_as_destination(tmp_path):
    original, profile, payloads = fixture()
    path = save_payload_manifest(tmp_path, original, profile, payloads)
    value = json.loads(path.read_text())
    value["format"] = "seep.recovered-payloads.v1"
    value["payloads"][0]["destination_rva"] = 1
    value["all_payload_crcs_verified"] = True
    path.write_text(json.dumps(value))
    assert load_payload_manifest(path, original, profile) == payloads


def test_wrong_manifest_identity_and_duplicate_are_rejected(tmp_path):
    original, profile, payloads = fixture()
    path = save_payload_manifest(tmp_path, original, profile, payloads)
    value = json.loads(path.read_text())
    value["baseline_sha256"] = "0" * 64
    path.write_text(json.dumps(value))
    with pytest.raises(RecoveryError, match="其他样本"):
        load_payload_manifest(path, original, profile)
    path = save_payload_manifest(tmp_path, original, profile, payloads)
    value = json.loads(path.read_text())
    value["payloads"].append(dict(value["payloads"][0]))
    path.write_text(json.dumps(value))
    with pytest.raises(RecoveryError):
        load_payload_manifest(path, original, profile)


@pytest.mark.parametrize("kind", [
    "root-list", "rows-not-list", "missing-rva", "non-string-path", "sensitive-field",
])
def test_malformed_manifest_is_a_typed_error_not_a_worker_crash(tmp_path, kind):
    original, profile, payloads = fixture()
    path = save_payload_manifest(tmp_path, original, profile, payloads)
    value = json.loads(path.read_text())
    if kind == "root-list":
        value = []
    elif kind == "rows-not-list":
        value["payloads"] = "wrong"
    elif kind == "missing-rva":
        del value["payloads"][0]["source_rva"]
    elif kind == "non-string-path":
        value["payloads"][0]["path"] = None
    else:
        value["payloads"][0]["key_prefix"] = [0] * 16  # synthetic prohibited field
    path.write_text(json.dumps(value))
    with pytest.raises(RecoveryError):
        load_payload_manifest(path, original, profile)


@pytest.mark.parametrize("case", ["baseline", "order", "crc", "range"])
def test_payload_validation_fails_closed(case):
    original, profile, payloads = fixture()
    if case == "baseline":
        original = original + b"wrong"
    elif case == "order":
        payloads = ()
    elif case == "crc":
        spec = replace(profile.payloads[0], crc32=0)
        profile = replace(profile, payloads=(spec,))
        payloads = (RecoveredPayload(spec, payloads[0].data),)
    elif case == "range":
        spec = replace(profile.payloads[0], size=len(original) * 2)
        profile = replace(profile, payloads=(spec,))
        payloads = (RecoveredPayload(spec, payloads[0].data),)
    with pytest.raises(RecoveryError):
        validate_payloads(original, profile, payloads)


def test_unknown_build_does_not_get_guessed_offsets():
    with pytest.raises(RecoveryError, match="未能从样本结构建立通用"):
        identify_profile(make_pe(32))


def test_service_keeps_original_and_reopens_transaction_roles(tmp_path, monkeypatch):
    original, profile, payloads = fixture()
    source = tmp_path / "original.exe"
    source.write_bytes(original)
    manifest = save_payload_manifest(tmp_path / "cache", original, profile, payloads)
    monkeypatch.setattr(recovery, "identify_profile", lambda _: profile)
    modified = original + b"MODIFIED"
    monkeypatch.setattr(recovery, "build_repair", lambda *args: BuiltRepair(
        modified, {"modified_sha256": sha256(modified)}, {"runtime_launch_verified": False}
    ))
    service = RepairService(compressor=lambda data: data)
    output = tmp_path / "custom.exe"
    result = service.repair(source, output, manifest=manifest)
    assert output.read_bytes() == modified
    assert source.read_bytes() == original
    assert json.loads(result.diff_path.read_text())["modified_sha256"] == sha256(modified)
    assert json.loads(result.verification_path.read_text())["runtime_launch_verified"] is False
    assert result.rollback_path.read_text().startswith("#!/bin/sh\n")
    assert output.with_name(output.name + ".baseline.exe").read_bytes() == original
    output.write_bytes(b"user-output")
    with pytest.raises(RecoveryError, match="--force"):
        service.repair(source, output, manifest=manifest)
    assert output.read_bytes() == b"user-output"
    service.repair(source, output, manifest=manifest, overwrite=True)
    assert source.read_bytes() == original


def test_service_rejects_source_and_hardlink_alias(tmp_path, monkeypatch):
    original, profile, _ = fixture()
    source = tmp_path / "original.exe"
    source.write_bytes(original)
    monkeypatch.setattr(recovery, "identify_profile", lambda _: profile)
    service = RepairService(compressor=lambda data: data)
    with pytest.raises(RecoveryError, match="副本"):
        service.repair(source, source)
    alias = tmp_path / "alias.exe"
    os.link(source, alias)
    with pytest.raises(RecoveryError, match="硬链接"):
        service.repair(source, alias)
    assert source.read_bytes() == original


def test_regular_import_does_not_load_optional_recovery_dependencies():
    code = (
        "import sys; import exerepair.cli; import exerepair.ui.viewmodel; "
        "assert not any(n in sys.modules for n in ('frida','numba','numpy'))"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_complete_unmodified_native_distribution_is_packaged():
    package = Path(recovery.__file__).parents[1] / "adapters/native/aPLib-1.1.1.zip"
    assert hashlib.sha256(package.read_bytes()).hexdigest() == ARCHIVE_SHA256
    with zipfile.ZipFile(package) as archive:
        assert "lib/dll64/aplib.dll" in archive.namelist()
        assert "lib/dll/aplib.dll" in archive.namelist()
        license_paths = [n for n in archive.namelist() if n.endswith("/license.txt")]
        assert license_paths
        assert b"You may not redistribute aPLib without all of the files." in archive.read(license_paths[0])


def _verify_helper(mode):
    import unicorn
    from unicorn import x86_const as r
    _original, _profile, payloads = fixture()
    code, no_op = helper_and_data(payloads)
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    address, descriptor, output, stack, stop = (
        0x10000000, 0x20000000, 0x21000000, 0x22000000, 0x23000000
    )
    for location in (address, descriptor, output, stack, stop):
        uc.mem_map(location, 4096)
    uc.mem_write(address, code)
    spec = payloads[0].spec
    desc = bytearray(80)
    struct.pack_into("<I", desc, 8, spec.size)
    struct.pack_into("<I", desc, 16, spec.source_rva if mode != "no-match" else 0xDEAD)
    uc.mem_write(descriptor, bytes(desc))
    uc.mem_write(output, b"X" * spec.size)
    sp = stack + 2048
    uc.mem_write(sp, struct.pack("<III", stop, 7, 8))
    registers = {
        r.UC_X86_REG_EAX: 0x13579BDF, r.UC_X86_REG_EBX: descriptor,
        r.UC_X86_REG_ECX: 0x2468ACE0, r.UC_X86_REG_EDX: 0x11223344,
        r.UC_X86_REG_ESI: output, r.UC_X86_REG_EDI: 32,
        r.UC_X86_REG_EBP: 0x401000, r.UC_X86_REG_ESP: sp,
        r.UC_X86_REG_EFLAGS: 0x602,  # DF=1: helper must restore, not just CLD
    }
    for register, value in registers.items():
        uc.reg_write(register, value)
    uc.emu_start(address + (no_op if mode == "ret8" else 0), stop, count=1000)
    assert bytes(uc.mem_read(output, spec.size)) == (
        payloads[0].data if mode == "copy" else b"X" * spec.size
    )
    for register, value in registers.items():
        expected = value + (12 if mode == "ret8" else 4) if register == r.UC_X86_REG_ESP else value
        assert uc.reg_read(register) == expected


@pytest.mark.parametrize("mode", ["copy", "no-match", "ret8"])
def test_native_helper_registers_flags_copy_and_stack(mode):
    if importlib.util.find_spec("unicorn") is None:
        pytest.skip("optional Unicorn verifier not installed")
    # Keep the native backend out of pytest's process. Its Windows SEH probes
    # can trigger pytest's fatal-handler diagnostics even when handled by QEMU.
    # A real crash here is a non-zero child exit and still fails this test.
    command = [
        sys.executable, "-c",
        f"from tests.test_runtime_repair import _verify_helper; _verify_helper({mode!r})",
    ]
    result = subprocess.run(command, capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert not result.stderr, result.stderr.decode(errors="replace")


def test_helper_rejects_empty_or_duplicate_table():
    with pytest.raises(RecoveryError):
        helper_and_data(())
    _original, _profile, payloads = fixture()
    with pytest.raises(RecoveryError):
        helper_and_data(payloads + payloads)
