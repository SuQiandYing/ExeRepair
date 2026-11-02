from __future__ import annotations

import os
from dataclasses import replace
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tkinter
from types import SimpleNamespace

import pytest

from exerepair.adapters import disc_discovery as runtime
from exerepair.application import recovery
from exerepair.application.recovery import RepairService
from exerepair.domain.recovery import RecoveryError
from exerepair.ui.viewmodel import ConsoleController, WorkflowKind
from exerepair.ui.view import MainWindow
from exerepair.workflows.disc_discovery import (
    bind_disc_evidence,
    bind_main_disc_evidence,
    discover_disc_candidate,
)
from exerepair.workflows.disc_repair import build_disc_repair
from exerepair.workflows.repair import sha256
from tests.test_disc_repair import fixture as disc_fixture


RETURN_GUARD = bytes.fromhex("8b45e88b4df464890d000000008be55dc3")
CALLER_GUARD = bytes.fromhex("9083f8050f8567010000")


def outer_image():
    original, _profile = disc_fixture()
    data = bytearray(original)
    bootstrap = (
        b"\x68" + struct.pack("<I", 0)
        + b"\x68" + struct.pack("<I", 1)
        + b"\x68" + struct.pack("<I", 0x400000)
        + b"\x68" + struct.pack("<I", 0x401000)
        + b"\xe9" + struct.pack("<i", 0)
    )
    data[0x400:0x400 + len(bootstrap)] = bootstrap
    return bytes(data)


def module_image(base=0x21000000, checker=0x1200, caller=0x2000, epilogue=0x1400, flag=0x3000):
    data = bytearray(0x5000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 0x1C, 0x10000000)
    struct.pack_into("<II", data, optional + 0x20, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 0x38, len(data), 0x200)
    struct.pack_into(
        "<8sIIIIIIHHI", data, 0x178, b".text\0\0\0",
        0x4000, 0x1000, 0x4000, 0x200, 0, 0, 0, 0, 0x60000020,
    )
    call_site = checker + 0x40
    data[checker:checker + 3] = b"\x55\x8b\xec"
    data[caller:caller + 3] = b"\x55\x8b\xec"
    data[call_site:call_site + 5] = b"\xe8" + struct.pack("<i", caller - call_site - 5)
    data[checker + 0x100:checker + 0x108] = (
        b"\x8b\x45\xe8\xa3" + struct.pack("<I", base + flag)
    )
    data[checker + 0x110:checker + 0x119] = (
        b"\x8b\x4d\xe8\x89\x0d" + struct.pack("<I", base + flag)
    )
    data[epilogue:epilogue + len(RETURN_GUARD)] = RETURN_GUARD
    data[caller + 0x4B:caller + 0x50] = b"\xe8\0\0\0\0"
    data[caller + 0x50:caller + 0x50 + len(CALLER_GUARD)] = CALLER_GUARD
    return bytes(data), base, caller + 0x50


def main_image():
    original = outer_image()
    base = 0x400000
    data = bytearray(0x2000)
    data[:0x400] = original[:0x400]
    first, message, second, callee = 0x1040, 0x1080, 0x10C0, 0x1180
    iat_call = b"\xff\x15" + struct.pack("<I", base + 0x11F0)
    data[first:first + 16] = (
        b"\xe8" + struct.pack("<i", callee - first - 5)
        + bytes.fromhex("83c40884c00f85") + struct.pack("<i", second + 16 - first - 16)
    )
    data[message:message + 10] = iat_call + bytes.fromhex("83f80175")
    data[second:second + 16] = (
        b"\xe8" + struct.pack("<i", callee - second - 5)
        + bytes.fromhex("83c40884c00f84") + struct.pack("<i", message - second - 16)
    )
    return bytes(data), base, message + 6


def main_register_image():
    main, base, _observed = main_image()
    data = bytearray(main)
    data[0x1000:0x1400] = bytes(0x400)
    first, message, second, callee = 0x1040, 0x1080, 0x10C0, 0x1180
    data[0x1020:0x1026] = b"\x8b\x1d" + struct.pack("<I", base + 0x11F0)
    data[first:first + 16] = (
        b"\xe8" + struct.pack("<i", callee - first - 5)
        + bytes.fromhex("83c40884c00f85") + struct.pack("<i", second + 12 - first - 16)
    )
    data[message:message + 6] = bytes.fromhex("ffd383f80175")
    data[second:second + 12] = (
        b"\xe8" + struct.pack("<i", callee - second - 5)
        + bytes.fromhex("83c40884c074")
        + struct.pack("<b", message - 8 - second - 12)
    )
    return bytes(data), base, message + 2


def bound_fixture():
    original = outer_image()
    module, base, caller = module_image()
    return original, bind_disc_evidence(
        discover_disc_candidate(original), original, module, base, caller,
    )


def test_static_candidate_is_bound_to_current_input():
    original = outer_image()
    profile = discover_disc_candidate(original)
    assert profile.requires_runtime_discovery
    assert profile.baseline_sha256 == sha256(original)
    assert profile.baseline_size == len(original)
    assert profile.entry_rva == 0x1000
    assert profile.module_image_size == 0


def test_runtime_evidence_derives_unique_check_and_builds():
    original = outer_image()
    pending = discover_disc_candidate(original)
    module, base, caller = module_image()
    profile = bind_disc_evidence(pending, original, module, base, caller)
    assert not profile.requires_runtime_discovery
    assert profile.module_image_size == len(module)
    assert profile.caller_return_rva == caller
    assert profile.caller_guard == CALLER_GUARD
    assert profile.return_rva == 0x1400
    assert profile.return_guard == RETURN_GUARD
    assert profile.success_flag_rva == 0x3000
    assert build_disc_repair(original, profile).report["patch_replay_verified"]


def test_main_evidence_binds_equal_length_branch_to_same_target():
    original, profile = bound_fixture()
    main, base, observed = main_image()
    result = bind_main_disc_evidence(profile, original, main, base, observed)
    assert result.region_ready_rva == 0x1040
    rva, before, after = result.region_patch_sites[0]
    assert rva == 0x104A
    assert before == main[rva:rva + 6]
    assert len(before) == len(after) == 6
    assert after[0] == 0xE9 and after[-1] == 0x90
    assert rva + 5 + struct.unpack_from("<i", after, 1)[0] == 0x10D0
    assert build_disc_repair(original, result).report["patch_replay_verified"]


def test_main_evidence_supports_observed_register_call_and_short_retry():
    original, profile = bound_fixture()
    main, base, observed = main_register_image()
    result = bind_main_disc_evidence(profile, original, main, base, observed)
    rva, before, after = result.region_patch_sites[0]
    assert before == main[rva:rva + 6]
    assert rva + 5 + struct.unpack_from("<i", after, 1)[0] == 0x10CC
    assert build_disc_repair(original, result).report["patch_replay_verified"]


def test_main_evidence_supports_short_success_and_retry_branches():
    original, profile = bound_fixture()
    main, base, observed = main_register_image()
    data = bytearray(main)
    data[0x10B0:0x10BC] = data[0x10C0:0x10CC]
    data[0x10C0:0x10CC] = bytes(12)
    struct.pack_into("<i", data, 0x10B1, 0x1180 - 0x10B5)
    struct.pack_into("<b", data, 0x10BB, 0x1078 - 0x10BC)
    data[0x1040:0x1050] = (
        b"\xe8" + struct.pack("<i", 0x1180 - 0x1045)
        + bytes.fromhex("83c40884c075") + struct.pack("<b", 0x10BC - 0x104C)
        + bytes(4)
    )
    result = bind_main_disc_evidence(profile, original, bytes(data), base, observed)
    rva, before, after = result.region_patch_sites[0]
    assert (rva, before[0], after[0]) == (0x104A, 0x75, 0xEB)
    assert rva + 2 + struct.unpack("<b", after[1:])[0] == 0x10BC
    assert build_disc_repair(original, result).report["patch_replay_verified"]


@pytest.mark.parametrize("offset", [0x1020, 0x10C1, 0x10CB])
def test_main_register_call_rejects_missing_or_unrelated_evidence(offset):
    original, profile = bound_fixture()
    main, base, observed = main_register_image()
    data = bytearray(main)
    data[offset] ^= 0xFF
    if offset == 0x1020:
        with pytest.raises(RecoveryError, match="导入槽"):
            bind_main_disc_evidence(profile, original, bytes(data), base, observed)
    else:
        result = bind_main_disc_evidence(profile, original, bytes(data), base, observed)
        assert not result.region_patch_sites


@pytest.mark.parametrize("damage", ["callee", "retry", "message", "condition"])
def test_main_evidence_does_not_patch_unrelated_patterns(damage):
    original, profile = bound_fixture()
    main, base, observed = main_image()
    data = bytearray(main)
    offsets = {
        "callee": 0x10C1,
        "retry": 0x10CC,
        "message": 0x1086,
        "condition": 0x104B,
    }
    data[offsets[damage]] ^= 1
    result = bind_main_disc_evidence(profile, original, bytes(data), base, observed)
    assert not result.region_patch_sites
    assert "未识别" in result.runtime_note


def test_main_evidence_rejects_mismatched_image_and_input():
    original, profile = bound_fixture()
    main, base, observed = main_image()
    with pytest.raises(RecoveryError, match="不匹配"):
        bind_main_disc_evidence(profile, original + b"x", main, base, observed)
    with pytest.raises(RecoveryError, match="基址"):
        bind_main_disc_evidence(profile, original, main, base + 0x1000, observed)
    broken = bytearray(main)
    broken[0x178 + 8] ^= 1
    with pytest.raises(RecoveryError, match="节布局"):
        bind_main_disc_evidence(profile, original, bytes(broken), base, observed)


@pytest.mark.parametrize(
    ("base", "checker", "caller", "epilogue", "flag"),
    [
        (0x18000000, 0x1300, 0x2100, 0x1500, 0x3100),
        (0x34000000, 0x1500, 0x2500, 0x1700, 0x3800),
    ],
)
def test_runtime_discovery_relocates_all_evidence(base, checker, caller, epilogue, flag):
    original = outer_image()
    module, base, observed = module_image(base, checker, caller, epilogue, flag)
    profile = bind_disc_evidence(
        discover_disc_candidate(original), original, module, base, observed
    )
    assert (profile.caller_return_rva, profile.return_rva, profile.success_flag_rva) == (
        caller + 0x50, epilogue, flag,
    )
    assert build_disc_repair(original, profile).report["patch_replay_verified"]


@pytest.mark.parametrize("damage", ["loader", "signature", "slots", "aslr"])
def test_static_candidate_rejects_unsafe_or_unrelated_pe(damage):
    data = bytearray(outer_image())
    if damage == "loader":
        data[0x400] ^= 1
    elif damage == "signature":
        struct.pack_into("<II", data, 0x98 + 96 + 4 * 8, 0x700, 32)
    elif damage == "slots":
        data[0x178 + 40] = 1
    else:
        struct.pack_into("<H", data, 0x98 + 0x46, 0x40)
        struct.pack_into("<II", data, 0x98 + 96 + 5 * 8, 0x1100, 8)
    with pytest.raises(RecoveryError):
        discover_disc_candidate(bytes(data))


@pytest.mark.parametrize(
    "damage",
    ["source", "header", "caller", "call_link", "first_store", "second_store", "flag"],
)
def test_runtime_evidence_fails_closed_for_invalid_structure(damage):
    original = outer_image()
    pending = discover_disc_candidate(original)
    module, base, caller = module_image()
    module = bytearray(module)
    if damage == "source":
        original += b"changed"
    elif damage == "header":
        module[0] = 0
    elif damage == "caller":
        module[caller + 2] ^= 1
    elif damage == "call_link":
        module[0x1241] ^= 1
    elif damage == "first_store":
        module[0x1300] ^= 1
    elif damage == "second_store":
        module[0x1310] ^= 1
    else:
        struct.pack_into("<I", module, 0x1304, base + len(module) + 4)
        struct.pack_into("<I", module, 0x1315, base + len(module) + 4)
    with pytest.raises(RecoveryError):
        bind_disc_evidence(pending, original, bytes(module), base, caller)


def test_runtime_evidence_rejects_multiple_matching_functions():
    original = outer_image()
    pending = discover_disc_candidate(original)
    module, base, caller = module_image()
    module = bytearray(module)
    # A second complete candidate targeting the same observed caller is ambiguous.
    module[0x1600:0x1603] = b"\x55\x8b\xec"
    module[0x1640:0x1645] = b"\xe8" + struct.pack("<i", 0x2000 - 0x1640 - 5)
    module[0x1700:0x1708] = b"\x8b\x45\xe8\xa3" + struct.pack("<I", base + 0x3000)
    module[0x1710:0x1719] = b"\x8b\x4d\xe8\x89\x0d" + struct.pack("<I", base + 0x3000)
    module[0x1800:0x1800 + len(RETURN_GUARD)] = RETURN_GUARD
    with pytest.raises(RecoveryError, match="唯一"):
        bind_disc_evidence(pending, original, bytes(module), base, caller)


def test_controller_drop_candidate_runs_verified_repair(tmp_path, monkeypatch):
    source = tmp_path / "input.exe"
    original = outer_image()
    source.write_bytes(original)
    module, base, caller = module_image()

    def discover(path, data, profile, *, progress):
        assert path == source
        assert data == original
        return replace(
            bind_disc_evidence(profile, data, module, base, caller),
            runtime_note="Synthetic runtime warning.",
        )

    monkeypatch.setattr(recovery, "discover_disc_runtime", discover)
    controller = ConsoleController()
    controller.begin_load(source)
    state = controller.load(source)
    assert state.can_act and state.workflow is WorkflowKind.REPAIR
    assert "运行时" in state.status_title
    assert "临时" in state.status_detail
    controller.begin_action()
    state, output = controller.act(tmp_path / "output.exe")
    assert state.can_act and output is not None
    assert "Synthetic runtime warning." in state.status_detail
    assert state.tone.value == "info"
    assert source.read_bytes() == original


def test_drop_accepts_a_quoted_path_with_spaces_and_ignores_busy_window():
    window = MainWindow.__new__(MainWindow)
    window.root = SimpleNamespace(tk=tkinter.Tcl())
    window._busy = False
    paths = []
    window.load_path = paths.append
    event = SimpleNamespace(data=r"{C:\folder with spaces\input.exe}")
    assert window._on_drop(event) == "break"
    assert paths == [r"C:\folder with spaces\input.exe"]
    window._busy = True
    assert window._on_drop(event) == "break"
    assert len(paths) == 1


def test_resource_directory_guides_probe_and_default_output(tmp_path, monkeypatch):
    source = tmp_path / "input.exe"
    original = outer_image()
    source.write_bytes(original)
    resources = tmp_path / "resources"
    resources.mkdir()
    (resources / "settings.dat").write_bytes(b"unchanged")
    module, base, caller = module_image()
    observed = []

    def discover(path, data, profile, *, progress, resource_dir):
        observed.append((path, resource_dir))
        return bind_disc_evidence(profile, data, module, base, caller)

    monkeypatch.setattr(recovery, "discover_disc_runtime", discover)
    controller = ConsoleController()
    controller.begin_load(source)
    state = controller.load(source)
    assert state.can_choose_resource_dir
    controller.set_disc_resource_dir(resources)
    controller.begin_action()
    state, output = controller.act()
    assert output == str(resources / "input_crack.exe")
    assert observed == [(source, resources)]
    assert source.read_bytes() == original
    assert (resources / "settings.dat").read_bytes() == b"unchanged"
    controller.set_disc_resource_dir(None)
    assert "disc_resource_dir" not in controller.recovery_options


def test_failed_probe_can_be_retried_after_selecting_resources(tmp_path, monkeypatch):
    source = tmp_path / "input.exe"
    source.write_bytes(outer_image())
    resources = tmp_path / "resources"
    resources.mkdir()
    module, base, caller = module_image()

    def discover(path, data, profile, *, progress, resource_dir=None):
        if resource_dir is None:
            raise RecoveryError("临时副本异常退出")
        return bind_disc_evidence(profile, data, module, base, caller)

    monkeypatch.setattr(recovery, "discover_disc_runtime", discover)
    controller = ConsoleController()
    controller.begin_load(source)
    controller.load(source)
    controller.begin_action()
    state, output = controller.act()
    assert output is None and state.phase == "error"
    assert state.can_act and state.can_choose_resource_dir
    controller.set_disc_resource_dir(resources)
    controller.begin_action()
    state, output = controller.act()
    assert state.phase == "ready"
    assert output == str(resources / "input_crack.exe")


def test_resource_directory_must_be_valid_and_does_not_override_source(tmp_path):
    source = tmp_path / "input.exe"
    source.write_bytes(outer_image())
    with pytest.raises((OSError, RecoveryError)):
        RepairService().repair(source, disc_resource_dir=tmp_path / "missing")
    with pytest.raises(RecoveryError, match="目录"):
        RepairService().repair(source, disc_resource_dir=source)


def test_pending_profile_cannot_be_built_without_runtime_evidence():
    original = outer_image()
    pending = discover_disc_candidate(original)
    with pytest.raises(RecoveryError, match="运行时"):
        build_disc_repair(original, pending)


def test_staged_resources_are_bounded_and_exclude_executables(tmp_path, monkeypatch):
    source = tmp_path / "input.exe"
    source.write_bytes(b"exe")
    (tmp_path / "a.dat").write_bytes(b"123")
    (tmp_path / "b.pac").write_bytes(b"456")
    (tmp_path / "ignored.exe").write_bytes(b"exe")
    (tmp_path / "oversized.ini").write_bytes(b"12345")
    destination = tmp_path / "probe"
    destination.mkdir()
    monkeypatch.setattr(runtime, "_MAX_RESOURCE", 4)
    monkeypatch.setattr(runtime, "_MAX_RESOURCES", 5)
    assert runtime._stage_resources(source.parent, destination) == 3
    assert [item.name for item in destination.iterdir()] == ["a.dat"]
    assert (tmp_path / "b.pac").read_bytes() == b"456"


def _verify_discovered_worker(mode):
    import unicorn as u
    from unicorn import x86_const as r

    from exerepair.workflows.disc_repair import disc_helper

    original, profile = bound_fixture()
    main, base, observed = main_register_image()
    profile = bind_main_disc_evidence(profile, original, main, base, observed)
    code_base, state_base = 0x50000000, 0x50010000
    stack, api, stop = 0x60000000, 0x70000000, 0x70000800
    code, state, layout = disc_helper(profile, code_base, state_base, base + 0x1000)
    uc = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    for address, size in (
        (base, 0x2000), (code_base, 0x1000), (state_base, 0x1000),
        (stack, 0x4000), (api, 0x1000),
    ):
        uc.mem_map(address, size)
    uc.mem_write(code_base, code)
    uc.mem_write(state_base, state)
    uc.mem_write(base, main)
    ready, guard = profile.region_ready_rva, profile.region_ready_bytes
    assert ready is not None
    site, expected, replacement = profile.region_patch_sites[0]
    if mode.startswith("guard-"):
        offset = int(mode.split("-")[1])
        uc.mem_write(base + ready + offset, bytes([guard[offset] ^ 1]))

    def put(address, *values):
        uc.mem_write(address, struct.pack("<" + "I" * len(values), *values))

    def read(address):
        return struct.unpack("<I", uc.mem_read(address, 4))[0]

    sp = stack + 0x1000
    put(sp, stop, 0)
    uc.reg_write(r.UC_X86_REG_ESP, sp)
    calls = []

    def stdcall(count, result):
        esp = uc.reg_read(r.UC_X86_REG_ESP)
        uc.reg_write(r.UC_X86_REG_EIP, read(esp))
        uc.reg_write(r.UC_X86_REG_ESP, esp + 4 * (count + 1))
        uc.reg_write(r.UC_X86_REG_EAX, result)

    def dispatch(_uc, address, _size, _data):
        esp = uc.reg_read(r.UC_X86_REG_ESP)
        if address == api:
            calls.append("query")
            put(read(esp + 8), base + 0x1000, base, 0x40, 0x1000, 0x1000, 0x20, 0x20000)
            stdcall(3, 28)
        elif address == api + 0x10:
            calls.append("sleep")
            uc.reg_write(r.UC_X86_REG_EDI, 1)
            stdcall(1, 0)
        elif address == api + 0x20:
            calls.append("protect")
            put(read(esp + 16), 0x20)
            stdcall(4, 1)
        elif address == api + 0x30:
            calls.append("flush")
            stdcall(3, 1)

    uc.hook_add(u.UC_HOOK_CODE, dispatch)
    put(state_base + 0x24, api)
    put(state_base + 0x30, api + 0x10)
    put(state_base + 0x04, api + 0x20)
    put(state_base + 0x20, api + 0x30)
    uc.emu_start(code_base + layout["region_worker_offset"], stop, count=10000)
    result = bytes(uc.mem_read(base + site, len(expected)))
    if mode == "success":
        assert result == replacement
        assert read(state_base + 0x38) == 1 and "flush" in calls
    else:
        assert "protect" not in calls and "sleep" in calls
        assert result != replacement
        assert read(state_base + 0x38) == 0


def test_discovered_worker_verifies_every_guard_byte_before_writing():
    if importlib.util.find_spec("unicorn") is None:
        pytest.skip("optional Unicorn verifier not installed")
    cases = ["success", *[f"guard-{index}" for index in range(16)]]
    result = subprocess.run(
        [
            sys.executable, "-B", "-c",
            "from tests.test_disc_discovery import _verify_discovered_worker; "
            f"[_verify_discovered_worker(mode) for mode in {cases!r}]",
        ],
        capture_output=True,
        timeout=30,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.skipif(os.name != "nt", reason="runtime probe requires Windows")
@pytest.mark.parametrize("valid", [True, False, "crash"])
def test_runtime_adapter_cleans_temporary_executable(tmp_path, monkeypatch, valid):
    source = tmp_path / "input.exe"
    original = outer_image()
    source.write_bytes(original)
    (tmp_path / "resource.dat").write_bytes(b"untouched")
    module, base, caller = module_image()
    main, main_base, message_return = main_image()
    events = []

    class Script:
        def on(self, _name, callback):
            self.callback = callback

        def load(self):
            pass

        def post(self, message):
            assert message["type"] == "disc_patch"
            assert message["epilogue"] == 0x1400
            assert message["flag"] == 0x3000
            events.append("patch")

    class Session:
        def on(self, _name, callback):
            self.detached = callback

        def create_script(self, _source):
            self.script = Script()
            return self.script

        def detach(self):
            events.append("detach")

    class Device:
        def spawn(self, arguments, *, cwd, stdio):
            self.probe = Path(arguments[0])
            assert self.probe.parent == Path(cwd)
            assert self.probe.read_bytes() == original
            assert {path.name for path in self.probe.parent.iterdir()} == {
                self.probe.name, "resource.dat",
            }
            assert (self.probe.parent / "resource.dat").read_bytes() == b"untouched"
            assert stdio == "pipe"
            return 1234

        def attach(self, pid):
            assert pid == 1234
            self.session = Session()
            return self.session

        def resume(self, pid):
            assert pid == 1234
            if valid is False:
                self.session.script.callback(
                    {"type": "send", "payload": {"event": "disc_error", "message": "probe failed"}},
                    module,
                )
                return
            self.session.script.callback(
                {
                    "type": "send",
                    "payload": {
                        "event": "disc_evidence",
                        "base": hex(base),
                        "caller_rva": caller,
                    },
                },
                module,
            )
            if valid == "crash":
                self.session.detached("process-terminated", None)
                return
            self.session.script.callback(
                {
                    "type": "send",
                    "payload": {
                        "event": "main_disc_evidence",
                        "base": hex(main_base),
                        "return_rva": message_return,
                    },
                },
                main,
            )

        def kill(self, pid):
            assert pid == 1234
            events.append("kill")

    device = Device()
    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_local_device=lambda: device))
    monkeypatch.setattr(runtime, "_open_probe_handle", lambda _pid: 99)
    monkeypatch.setattr(runtime, "_probe_exit_code", lambda _handle: 0xC0000005)
    monkeypatch.setattr(runtime, "_close_probe_handle", lambda _handle: events.append("close"))
    monkeypatch.setattr(runtime, "_wait_for_probe_exit", lambda _pid: events.append("wait"))
    pending = discover_disc_candidate(original)
    if valid is True:
        result = runtime.discover_disc_runtime(source, original, pending)
        assert result.return_rva == 0x1400
    elif valid == "crash":
        with pytest.raises(RecoveryError, match="0xC0000005"):
            runtime.discover_disc_runtime(source, original, pending)
    else:
        with pytest.raises(RecoveryError, match="probe failed"):
            runtime.discover_disc_runtime(source, original, pending)
    assert events == (
        ["patch", "kill", "wait", "detach", "close"]
        if valid else ["kill", "wait", "detach", "close"]
    )
    assert not device.probe.parent.exists()
    assert source.read_bytes() == original
    assert (tmp_path / "resource.dat").read_bytes() == b"untouched"
