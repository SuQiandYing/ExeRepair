from __future__ import annotations

from pathlib import Path

from exerepair.application import ExtractionOptions, ContainerService
from exerepair.domain.errors import ErrorCode, LoadError
from exerepair.stub import ContainerFlags
from tests.helpers import make_embedded_wrapper, make_pe, make_stub


def _wrapper(tmp_path: Path) -> Path:
    executable = make_pe(32)
    stub, align_size = make_stub(
        0x34576453,
        int(ContainerFlags.UseExecutableFileNameArgument),
        executable_name="game.exe",
    )
    path = tmp_path / "wrapped.exe"
    path.write_bytes(make_embedded_wrapper(stub, align_size, executable))
    return path


def test_service_returns_immutable_load_and_result_objects(tmp_path) -> None:
    path = _wrapper(tmp_path)
    service = ContainerService()
    loaded = service.load(path)
    assert loaded.source_path == path.resolve()
    assert loaded.executable_version == "PE32"
    assert loaded.wrapper_size > 0
    report = service.inspect(path)
    assert report.stub_level == "V4"
    assert len(report.patches) == 256

    output = tmp_path / "result"
    result = service.extract_loaded(
        loaded, ExtractionOptions(output_directory=output)
    )
    assert result.success
    assert result.output_directory == output.resolve()
    assert result.failures == ()
    assert result.last_error == ""
    assert (output / "wrapped.exe").is_file()


def test_service_uses_typed_error_codes(tmp_path) -> None:
    try:
        ContainerService().load(tmp_path / "missing.exe")
    except LoadError as error:
        assert error.code is ErrorCode.FILE_NOT_FOUND
        assert error.message == "容器主程序文件不存在"
    else:
        raise AssertionError("missing wrapper must fail")
