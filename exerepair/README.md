# 包入口、公共 API 与命令行

本目录连接命令行、桌面入口和公共 API，具体格式与处理用例分别放在子目录。
`__init__.py` 导出容器接口和版本；`api.py` 汇总容器与修复接口；
`__main__.py` 提供模块式 CLI 入口。`crypto.py`、`pe.py`、`stub.py`
是兼容导出层，不重复维护算法实现。

## 功能流程

- `cli.main()` 先解析参数；无输入或 `--gui` 时延迟进入桌面入口。
- 有输入时先加载容器；加载失败且文件存在时尝试修复参数匹配。
- `--inspect` 只打印信息；处理动作分别调用容器或修复应用服务。
- `WrappedProgram` 保留上一次加载、错误和输出位置，供有状态脚本使用。

## 主要契约

`ContainerService` 的加载失败是带错误码的 `OperationError`；
`RepairService` 对未知身份或无效证据返回 `RecoveryError`。
`WrappedProgram.load()` 将预期加载错误转换为 `False` 和 `last_error`；
`extract()` 在未加载时返回 `False`。CLI 的 API 参数不等同于 Tk 控件操作。

推荐集成导入 `exerepair.api`；不需要 GUI 的调用不应主动导入 `ui.view`。
参数范围、默认输出和返回码见根目录 README。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`PEFile`、`PEFormatError`、`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`PatchFailure`、`PatchInfo`、`ProgramExtractor`、`ProgramLoader`、`RandomV1`、`ContainerFlags`、`PatchRecord`、`WrappedProgram`、`ContainerService`、`crc32`、`xor_in_place`。

此文件导入/转发：`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`PatchFailure`、`PatchInfo`、`ProgramExtractor`、`ProgramLoader`、`ContainerService`、`RandomV1`、`crc32`、`xor_in_place`、`ContainerFlags`、`PatchRecord`、`PEFile`、`PEFormatError`、`WrappedProgram`。


### `__main__.py`

模块式执行入口，将退出状态交给 CLI；与已安装命令共享实现。

此文件导入/转发：`main`。


### `api.py`

聚合容器服务、修复服务、结果对象和类型化错误，供脚本集成。
光盘检查流程另外导出不可变 `DiscCheckProfile` 与 `PortableSetupProfile`；
后者描述可选安装目录调用替换，前者的 `portable_setup` 默认是 `None`。
处理仍调用同一个
`RepairService.inspect()` / `repair()`，不需要专用的入口脚本。

公开导出：`ErrorCode`、`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`PatchFailure`、`PatchInfo`、`ExtractError`、`LoadError`、`OperationError`、`WrappedProgram`、`ContainerService`、`RepairService`、`RecoveryError`、`RepairInspection`、`RepairResult`。

此文件导入/转发：`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`PatchFailure`、`PatchInfo`、`ContainerService`、`ErrorCode`、`ExtractError`、`LoadError`、`OperationError`、`WrappedProgram`、`RepairService`、`RecoveryError`、`RepairInspection`、`RepairResult`。


### `cli.py`

组装参数、选择 GUI/容器/修复流程、打印状态并返回退出码。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_path_options(parser: argparse.ArgumentParser) -> None` | 添加输入、只读检查、输出、GUI 与覆盖选项。 |
| `_recovery_options(parser: argparse.ArgumentParser) -> None` | 添加清单、工作目录、压缩器、后端与有界搜索选项。 |
| `build_parser() -> argparse.ArgumentParser` | 返回完整 argparse 解析器，不执行处理。 |
| `_print_program(program) -> None` | 按固定字段顺序打印容器、主程序及有效区块信息。 |
| `_inspect_or_repair(target: Path, args) -> int` | 匹配修复配置；只读模式打印后返回，否则执行修复并打印事务结果。 |
| `main(argv: list[str] &#124; None=None) -> int` | 解析本模块参数并执行所述入口；返回退出状态，具体输入见本节说明。 |


### `crypto.py`

从 security 兼容导出 CRC32、RandomV1 和 XOR。

公开导出：`RandomV1`、`crc32`、`xor_in_place`。

此文件导入/转发：`RandomV1`、`xor_in_place`、`crc32`。


### `pe.py`

从formats.pe兼容导出PE类型。

公开导出：`PEFile`、`PEFormatError`。

此文件导入/转发：`PEFile`、`PEFormatError`。


### `program.py`

有状态容器门面：保存加载对象、错误消息和最后输出目录。

#### `WrappedProgram`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `WrappedProgram.__init__(self, service: ContainerService &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `WrappedProgram.stub(self) -> ContainerStub &#124; None` | 只读属性：规范化容器配置；兼容名称不维护独立数据。 |
| `WrappedProgram.executable_version(self) -> str` | 只读属性：主程序PE位数描述；兼容名称不维护独立数据。 |
| `WrappedProgram.executable_size(self) -> int` | 只读属性：主程序字节数；兼容名称不维护独立数据。 |
| `WrappedProgram.size(self) -> int` | 只读属性：字节大小；兼容名称不维护独立数据。 |
| `WrappedProgram.last_error(self) -> str` | 只读属性：last_error 当前状态；兼容名称不维护独立数据。 |
| `WrappedProgram.is_valid(self) -> bool` | 只读属性：is_valid 当前状态；兼容名称不维护独立数据。 |
| `WrappedProgram.output_directory(self) -> Path &#124; None` | 只读属性：生成内容所在目录；兼容名称不维护独立数据。 |
| `WrappedProgram.load(self, executable_path: str &#124; Path) -> bool` | 加载容器并重置输出状态；预期错误返回 False，同时保存消息。 |
| `WrappedProgram.extract(self, output_directory: str &#124; Path &#124; None=None) -> bool` | 处理已加载对象；返回 success，并保存输出目录与最后错误。 |


### `stub.py`

从formats.stub兼容导出容器解析。

此文件导入/转发：`format_container_flags`、`*`。


## 子目录

- [adapters](adapters/README.md)：详细模块与功能说明。

- [application](application/README.md)：详细模块与功能说明。

- [domain](domain/README.md)：详细模块与功能说明。

- [formats](formats/README.md)：详细模块与功能说明。

- [security](security/README.md)：详细模块与功能说明。

- [ui](ui/README.md)：详细模块与功能说明。

- [workflows](workflows/README.md)：详细模块与功能说明。

## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_cli.py tests/test_program.py tests/test_application.py -q
```

[返回项目总说明](../README.md)
