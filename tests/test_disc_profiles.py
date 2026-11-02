from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from exerepair import cli
from exerepair.api import load_disc_profile
from exerepair.application.recovery import RepairService
from exerepair.domain.recovery import RecoveryError
from exerepair.ui.viewmodel import ConsoleController, WorkflowKind
from exerepair.workflows import profiles
from exerepair.workflows.repair import apply_binary_patch
from tests.test_disc_repair import fixture as disc_fixture


def _document(profile):
    return {
        "format": "exerepair.disc-profile.v1",
        "name": profile.name,
        "baseline_sha256": profile.baseline_sha256,
        "baseline_size": profile.baseline_size,
        "image_base": hex(profile.image_base),
        "entry_rva": hex(profile.entry_rva),
        "entry_bytes": profile.entry_bytes.hex(),
        "module_image_size": hex(profile.module_image_size),
        "caller_return_rva": hex(profile.caller_return_rva),
        "caller_guard": profile.caller_guard.hex(),
        "return_rva": hex(profile.return_rva),
        "return_guard": profile.return_guard.hex(),
        "success_flag_rva": hex(profile.success_flag_rva),
        "allow_dynamic_base_without_relocations": profile.allow_dynamic_base_without_relocations,
        "runtime_note": profile.runtime_note,
    }


@pytest.fixture
def external(tmp_path):
    original, profile = disc_fixture()
    profile = replace(profile, runtime_note="Check compatible external resources")
    source = tmp_path / "input.exe"
    source.write_bytes(original)
    config = tmp_path / "profile.json"
    config.write_text(json.dumps(_document(profile)), encoding="utf-8")
    return source, config, original, profile


def test_explicit_profile_repair_replays_without_global_registration(external, tmp_path):
    source, config, original, profile = external
    old_profiles = profiles.PROFILES
    assert load_disc_profile(config) == profile
    service = RepairService()
    assert service.inspect(source, disc_profile=config).profile == profile
    output = tmp_path / "result.exe"
    result = service.repair(source, output, disc_profile=config)
    assert source.read_bytes() == original
    assert profiles.PROFILES is old_profiles
    assert apply_binary_patch(original, json.loads(result.diff_path.read_text())) == output.read_bytes()
    report = json.loads(result.verification_path.read_text())
    assert report["runtime_note"] == profile.runtime_note
    assert report["runtime_launch_verified"] is False


def test_external_profile_rejects_mismatched_input_before_writing(external, tmp_path):
    source, config, original, _ = external
    source.write_bytes(original + b"x")
    output = tmp_path / "output.exe"
    with pytest.raises(RecoveryError, match="SHA-256"):
        RepairService().repair(source, output, disc_profile=config)
    assert not output.exists()


def test_external_profile_is_not_overwritten_even_with_force(external, tmp_path):
    source, config, _, _ = external
    original_config = config.read_bytes()
    service = RepairService()
    with pytest.raises(RecoveryError, match="外部光盘配置"):
        service.repair(source, config, disc_profile=config, overwrite=True)
    alias = tmp_path / "profile-alias.exe"
    os.link(config, alias)
    with pytest.raises(RecoveryError, match="外部光盘配置"):
        service.repair(source, alias, disc_profile=config, overwrite=True)
    assert config.read_bytes() == original_config


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format", "unexpected"),
        ("name", ""),
        ("baseline_sha256", "bad"),
        ("baseline_size", 0),
        ("baseline_size", True),
        ("entry_rva", "-1"),
        ("entry_rva", 0x100000000),
        ("entry_bytes", "zzz"),
        ("caller_guard", "00"),
        ("return_guard", "00"),
        ("module_image_size", 1),
        ("allow_dynamic_base_without_relocations", "true"),
        ("runtime_note", ["not text"]),
    ],
)
def test_external_profile_rejects_invalid_fields(external, tmp_path, field, value):
    _, _, _, profile = external
    document = _document(profile)
    document[field] = value
    config = tmp_path / "invalid.json"
    config.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RecoveryError):
        load_disc_profile(config)


def test_external_profile_rejects_missing_unknown_duplicate_and_oversized(external, tmp_path):
    _, _, _, profile = external
    document = _document(profile)
    config = tmp_path / "invalid.json"
    missing = dict(document)
    del missing["return_rva"]
    config.write_text(json.dumps(missing), encoding="utf-8")
    with pytest.raises(RecoveryError, match="缺少"):
        load_disc_profile(config)
    config.write_text(json.dumps(dict(document, unexpected=True)), encoding="utf-8")
    with pytest.raises(RecoveryError, match="未知"):
        load_disc_profile(config)
    config.write_text('{"name":"one","name":"two"}', encoding="utf-8")
    with pytest.raises(RecoveryError, match="重复"):
        load_disc_profile(config)
    config.write_bytes(b" " * 65537)
    with pytest.raises(RecoveryError, match="大小"):
        load_disc_profile(config)
    config.write_bytes(b"\xff")
    with pytest.raises(RecoveryError, match="UTF-8 JSON"):
        load_disc_profile(config)


def test_cli_uses_external_profile_without_container_fallback(external, tmp_path, monkeypatch, capsys):
    source, config, original, profile = external

    def unexpected_container(*_args, **_kwargs):
        pytest.fail("explicit profile must not fall back to container extraction")

    monkeypatch.setattr(cli.ContainerService, "load", unexpected_container)
    assert cli.main(["--inspect", str(source), "--disc-profile", str(config)]) == 0
    output_text = capsys.readouterr().out
    assert profile.name in output_text
    assert profile.runtime_note in output_text
    output = tmp_path / "output.exe"
    assert cli.main([str(source), "--disc-profile", str(config), "-o", str(output)]) == 0
    assert source.read_bytes() == original
    assert output.is_file()


def test_controller_uses_external_profile_and_reports_mismatch(external, tmp_path, monkeypatch):
    source, config, original, profile = external
    controller = ConsoleController(recovery_options={"disc_profile": config})

    def unexpected_container(*_args, **_kwargs):
        pytest.fail("explicit profile must not fall back to container extraction")

    monkeypatch.setattr(controller.service, "load", unexpected_container)
    controller.begin_load(source)
    state = controller.load(source)
    assert state.can_act and state.workflow is WorkflowKind.REPAIR
    assert profile.runtime_note in state.status_detail
    state, output = controller.act(tmp_path / "output.exe")
    assert output is not None and profile.runtime_note in state.status_detail
    source.write_bytes(original + b"x")
    controller.begin_load(source)
    state = controller.load(source)
    assert not state.can_act
    assert state.status_title == "外部配置检查失败"
    assert "SHA-256" in state.status_detail


@pytest.mark.parametrize("mode", ("--run", "--enigma"))
def test_cli_rejects_external_profile_in_unrelated_modes(external, mode):
    source, config, _, _ = external
    with pytest.raises(SystemExit) as error:
        cli.main([str(source), mode, "--disc-profile", str(config)])
    assert error.value.code == 2


def test_cli_passes_external_profile_to_gui(external, monkeypatch):
    source, config, _, _ = external
    captured = {}

    def gui(path, *, recovery_options):
        captured["path"] = Path(path)
        captured["options"] = recovery_options
        return 0

    monkeypatch.setattr("exerepair.ui.main", gui)
    assert cli.main([str(source), "--gui", "--disc-profile", str(config)]) == 0
    assert captured["path"] == source
    assert captured["options"]["disc_profile"] == config
