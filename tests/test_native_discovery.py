import os
from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from exerepair.adapters import native_discovery as runtime
from exerepair.domain.recovery import NativeCallProfile, RecoveryError
from exerepair.workflows.native_discovery import (
    bind_runtime_evidence, discover_native_static,
)
from exerepair.workflows.profiles import NATIVE_CALL_X86_V1, identify_profile
from exerepair.workflows.repair import sha256


# Optional developer fixture.  Keep machine-specific locations out of the
# source tree; callers can point at a local sample through an environment
# variable when they have the matching authorized fixture.
TP03 = Path(os.environ.get("EXEREPAIR_TP03_FIXTURE", "fixtures/tp03.exe"))


@pytest.mark.skipif(not TP03.is_file(), reason="local native fixture is unavailable")
def test_unknown_enigma_build_uses_structural_profile_not_game_registry():
    data = TP03.read_bytes()
    profile = identify_profile(data)
    assert isinstance(profile, NativeCallProfile)
    assert profile.requires_runtime_discovery is True
    assert profile.name.startswith("enigma-1.31-native-call-candidate")
    assert profile.dispatch_rva == 0x133AFE
    assert profile.dispatch_global_rva == 0x1BA8A4
    assert profile.engine_base_delta == 0x113000
    assert len(profile.bootstrap_size_offsets) == 2
    assert len(profile.bootstrap_source_offsets) == 2


@pytest.mark.skipif(not TP03.is_file(), reason="local native fixture is unavailable")
def test_runtime_evidence_binds_only_unique_executeapi_call():
    data = TP03.read_bytes()
    static = discover_native_static(data)
    evidence = {
        "signature_rva": 0x1845D,
        "guard_rva": 0x18486,
        "call_rva": 0x1848B,
        "return_rva": 0x1848D,
        "guard_bytes": "68046a4d00ffd083c404",
        "main_base": "0x400000",
        "module_rva": 0xD6A1C,
        "name_rva": 0xD6A10,
        "module_name": "plugin.dll",
        "export": "executeAPI",
        "candidate_count": 1,
    }
    bound = bind_runtime_evidence(static, data, evidence)
    assert bound.requires_runtime_discovery is False
    assert bound.call_rva == 0x1848B
    with pytest.raises(RecoveryError, match="唯一"):
        bind_runtime_evidence(
            static, data, {**evidence, "candidate_count": 2}
        )


def test_static_discovery_rejects_non_enigma_bytes():
    with pytest.raises(RecoveryError):
        discover_native_static(b"not-a-pe")


def test_copy_probe_tree_excludes_the_probe_but_preserves_nested_resources(tmp_path):
    source = tmp_path / "game.exe"
    source.write_bytes(b"game")
    (tmp_path / "resource.dat").write_bytes(b"resource")
    resources = tmp_path / "custom-work"
    resources.mkdir()
    (resources / "nested.dat").write_bytes(b"nested")
    destination = resources / "native-probe"
    probe = runtime._copy_probe_tree(source, destination)
    assert probe.read_bytes() == b"game"
    assert (destination / "resource.dat").read_bytes() == b"resource"
    assert (destination / "custom-work" / "nested.dat").read_bytes() == b"nested"
    assert not (destination / "custom-work" / "native-probe").exists()


def _native_probe_fixture(tmp_path, monkeypatch, *, registration=False, delayed=False):
    source_dir = tmp_path / "game"
    source_dir.mkdir()
    source = source_dir / "game.exe"
    original = b"fixture"
    source.write_bytes(original)
    work_dir = tmp_path / "work"
    static = replace(
        NATIVE_CALL_X86_V1,
        baseline_sha256=sha256(original),
        baseline_size=len(original),
        requires_runtime_discovery=True,
    )
    bound = replace(static, requires_runtime_discovery=False)
    events = []
    clock = [0.0]

    class Script:
        exports_sync = SimpleNamespace(configure=lambda _sections: None)

        def on(self, _name, callback):
            self.callback = callback

        def load(self):
            pass

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
            assert stdio == "pipe"
            clock[0] = 100.0  # Staging time does not consume the runtime deadline.
            return 1234

        def attach(self, _pid):
            self.session = Session()
            return self.session

        def resume(self, _pid):
            events.append("resume")

        def kill(self, _pid):
            events.append("kill")

    device = Device()
    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_local_device=lambda: device))
    monkeypatch.setattr(runtime.PEImage, "parse", lambda _: SimpleNamespace(sections=()))
    monkeypatch.setattr(runtime, "_wait_for_probe_exit", lambda _pid: events.append("wait"), raising=False)
    monkeypatch.setattr(runtime, "_registration_dialog_visible", lambda _pid: registration, raising=False)
    monkeypatch.setattr(runtime, "bind_runtime_evidence", lambda *_args: bound)
    monkeypatch.setattr(runtime, "save_native_cache", lambda *_args: None)
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])

    def sleep(seconds):
        clock[0] += seconds
        if delayed:
            device.session.script.callback({
                "type": "send",
                "payload": {"event": "native_call_evidence", "evidence": {"ok": True}},
            }, None)

    monkeypatch.setattr(runtime.time, "sleep", sleep)
    return source, original, work_dir, static, bound, device, events


@pytest.mark.skipif(os.name != "nt", reason="runtime probe requires Windows")
def test_native_probe_waits_after_kill_and_reports_registration_window(tmp_path, monkeypatch):
    source, original, work_dir, static, _, device, events = _native_probe_fixture(
        tmp_path, monkeypatch, registration=True,
    )
    with pytest.raises(RecoveryError, match="注册窗口"):
        runtime.discover_native_runtime(source, original, static, work_dir, timeout=0)
    assert events == ["resume", "kill", "wait", "detach"]
    assert not device.probe.parent.exists()
    assert source.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="runtime probe requires Windows")
def test_native_probe_deadline_starts_after_staging(tmp_path, monkeypatch):
    source, original, work_dir, static, bound, device, events = _native_probe_fixture(
        tmp_path, monkeypatch, delayed=True,
    )
    result = runtime.discover_native_runtime(source, original, static, work_dir, timeout=1)
    assert result == bound
    assert events == ["resume", "kill", "wait", "detach"]
    assert not device.probe.parent.exists()
