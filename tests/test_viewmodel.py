from __future__ import annotations

from pathlib import Path

from exerepair.application import ContainerService
from exerepair.ui.viewmodel import (
    ConsoleController,
    StatusTone,
    WorkflowKind,
)
from exerepair.domain.models import ContainerFlags
from tests.helpers import make_embedded_wrapper, make_pe, make_stub
from exerepair.domain.recovery import RepairInspection
from exerepair.workflows.profiles import TAYUTAMA_ZERO
from types import SimpleNamespace


def _wrapper(tmp_path: Path) -> Path:
    stub, align = make_stub(
        0x34576453,
        int(ContainerFlags.UseExecutableFileNameArgument),
        executable_name="game.exe",
    )
    path = tmp_path / "wrapped.exe"
    path.write_bytes(make_embedded_wrapper(stub, align, make_pe(32)))
    return path


def test_controller_unwrap_flow(tmp_path) -> None:
    path = _wrapper(tmp_path)
    controller = ConsoleController(ContainerService())

    state = controller.begin_load(path)
    assert state.phase == "loading"
    assert not state.can_act

    state = controller.load(path)
    assert state.phase == "ready"
    assert state.tone is StatusTone.SUCCESS
    assert state.can_act
    assert state.workflow is WorkflowKind.UNWRAP
    assert state.action_label == "提取"

    state = controller.begin_action()
    assert state.phase == "busy"

    state, output = controller.act()
    assert output is not None
    assert Path(output).name == "wrapped_crack.exe"
    assert Path(output).is_file()
    assert state.phase == "ready"
    assert state.status_title == "提取完成"
    assert state.can_act


def test_controller_error_state_is_stable(tmp_path) -> None:
    controller = ConsoleController()
    controller.begin_load(tmp_path / "missing.exe")
    state = controller.load(tmp_path / "missing.exe")
    assert state.phase == "error"
    assert state.tone is StatusTone.ERROR
    assert not state.can_act


def test_controller_target_only_flow_respects_custom_output(tmp_path) -> None:
    source = tmp_path / "game.exe"
    source.write_bytes(make_pe(32))
    output = tmp_path / "chosen.exe"
    calls = []

    class FakeRepairService:
        def inspect(self, path):
            return RepairInspection(Path(path), TAYUTAMA_ZERO, 1, 0x400000, 4096, 13)

        def repair(self, target, destination, **options):
            calls.append((target, destination, options))
            options["progress"]("fixture complete")
            return SimpleNamespace(output_path=destination)

    controller = ConsoleController(repair_service=FakeRepairService())
    controller.begin_load(source)
    state = controller.load(source)
    assert state.workflow is WorkflowKind.REPAIR
    assert state.can_act
    assert state.action_label == "修复副本"
    controller.begin_action()
    state, produced = controller.act(output)
    assert produced == str(output)
    assert calls[0][0] == source
    assert calls[0][1] == output
    assert calls[0][2].get("overwrite", False) is False
    assert state.status_title == "修复副本已生成"
    assert controller.reset().can_act is False
