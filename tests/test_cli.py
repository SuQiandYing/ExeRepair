from __future__ import annotations

from pathlib import Path

from exerepair.cli import main
from exerepair.domain.models import ContainerFlags
from tests.helpers import make_embedded_wrapper, make_pe, make_stub
from types import SimpleNamespace
from exerepair import cli
from exerepair.workflows.profiles import TAYUTAMA_ZERO


def _wrapper(tmp_path: Path) -> Path:
    stub, align = make_stub(
        0x34576453,
        int(ContainerFlags.UseExecutableFileNameArgument),
        executable_name="game.exe",
    )
    path = tmp_path / "wrapped.exe"
    path.write_bytes(make_embedded_wrapper(stub, align, make_pe(32)))
    return path


def test_cli_exit_codes_and_output(tmp_path, capsys) -> None:
    assert main([str(tmp_path / "missing.exe")]) == 2

    path = _wrapper(tmp_path)
    assert main(["--inspect", str(path)]) == 0
    output = capsys.readouterr().out
    assert "版本: V4" in output
    assert "主程序版本: PE32" in output

    destination = tmp_path / "wrapped_crack.exe"
    assert main(["-o", str(destination), str(path)]) == 0
    assert "提取成功:" in capsys.readouterr().out
    assert destination.is_file()


def test_cli_target_only_route_and_explicit_options(tmp_path, monkeypatch, capsys):
    source = tmp_path / "plain.exe"
    source.write_bytes(make_pe(32))
    output = tmp_path / "custom.exe"
    manifest = tmp_path / "manifest.json"
    calls = []

    class FakeService:
        def inspect(self, path):
            return SimpleNamespace(profile=TAYUTAMA_ZERO)

        def repair(self, target, destination, **options):
            calls.append((target, destination, options))
            return SimpleNamespace(
                output_path=destination, output_sha256="fixture",
                diff_path=output.with_suffix(".json"), verification_path=output.with_suffix(".txt"),
                rollback_path=output.with_suffix(".sh"),
            )

    monkeypatch.setattr(cli, "RepairService", FakeService)
    assert main(["--inspect", str(source)]) == 0
    assert not calls
    assert main([str(source), "--recovery-manifest", str(manifest), "-o", str(output)]) == 0
    assert calls[0][1] == output
    assert calls[0][2]["manifest"] == manifest
    assert calls[0][2]["overwrite"] is False
    assert "修复配置:" in capsys.readouterr().out
