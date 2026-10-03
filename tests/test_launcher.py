from __future__ import annotations

from pathlib import Path

from exerepair import cli
from exerepair.launcher import LaunchResult, launch_from_folder


class _FakeProcess:
    pid = 4242

    def wait(self, timeout=None):
        assert timeout == 3
        return 0


def test_launch_from_folder_passes_parent_as_cwd(tmp_path, monkeypatch) -> None:
    source = tmp_path / "星空TeaParty.exe"
    source.write_bytes(b"MZ")
    calls = []

    def fake_popen(command, *, cwd, shell):
        calls.append((command, cwd, shell))
        return _FakeProcess()

    monkeypatch.setattr("exerepair.launcher.subprocess.Popen", fake_popen)
    result = launch_from_folder(source, ("--safe",), wait=True, timeout=3)

    assert calls == [([str(source), "--safe"], str(tmp_path), False)]
    assert result == LaunchResult(source.resolve(), tmp_path.resolve(), 4242, 0)


def test_cli_run_reports_working_directory(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "星空TeaParty.exe"
    result = LaunchResult(source.resolve(), tmp_path.resolve(), 4242, None)
    calls = []

    def fake_launch(path, arguments, *, wait, timeout):
        calls.append((path, arguments, wait, timeout))
        return result

    monkeypatch.setattr(cli, "launch_from_folder", fake_launch)
    assert cli.main([
        "--run",
        str(source),
        "--launch-arg=--safe",
    ]) == 0

    assert calls == [(Path(str(source)), ["--safe"], False, None)]
    output = capsys.readouterr().out
    assert f"启动文件: {source.resolve()}" in output
    assert f"工作目录: {tmp_path.resolve()}" in output
    assert "状态: 已启动" in output


def test_cli_rejects_timeout_without_wait(tmp_path, monkeypatch) -> None:
    source = tmp_path / "game.exe"

    def unexpected_launch(*args, **kwargs):
        raise AssertionError("invalid arguments must not launch")

    monkeypatch.setattr(cli, "launch_from_folder", unexpected_launch)
    try:
        cli.main(["--run", str(source), "--timeout", "1"])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("--timeout without --wait should be rejected")
