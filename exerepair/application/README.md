# 应用层：加载、提取与修复事务

应用层负责把格式、纯字节构建器和外部适配器组合为可调用用例，并返回结果对象。

## 功能流程

### 容器加载

`ProgramLoader` 注入文件系统、PE 和 stub 解析器。只读源文件，要求外壳 PE32，
读取 Overlay 配置后选择内嵌或外置主程序，并验证主程序 PE32/PE64。
`LoadedProgram` 保存输入身份、已解析格式与主程序字节，不在加载时写输出。

### 容器提取

`ProgramExtractor` 按输出选项确定目录，复制主程序字节并逐个处理补丁。
`ExecutableOnly` 用文件偏移；`Memory` 用 RVA 转换；`File` 复制并修改资源。
区块失败记录索引与原因，进度回调报告每次循环；可选取消回调在区块之间检查。
资源路径规范化，多个补丁命中同一资源时只先复制一次。
该流程可能留下部分输出，并没有修复事务的 no-clobber / 回滚发布机制。

### 单目标修复

`RepairService.inspect()` 只读匹配身份并解析 PE。
`repair()` 区分载荷与原生配置：原生配置拒绝清单；
载荷配置优先重算缓存校验，无缓存才加载可选捕获/搜索依赖。
构建器返回 `BuiltRepair` 后共用别名检查、覆盖检查、原子发布、重读和原文件校验。

## 输入、结果与错误

`ExtractionOptions` 中 `output_exe` 优先于 `output_directory`，两者均空时用默认目录。
`ExtractionResult.success` 仅在所有有效补丁通过且主程序写入成功时为真。
`last_error` 优先给出操作级错误，否则格式化失败索引。
修复输出通过 `RepairResult` 返回 EXE、差异、验证、回滚位置与载荷数量。

缓存清单不信任自报校验标志；相对载荷路径从清单所在目录解释。
修复文件逐一原子发布，并非多个文件共同提交。构建错误、缓存错误或冲突
会阻止后续步骤；文件级成功不自动启动游戏。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`LoadedProgram`、`PatchFailure`、`PatchInfo`、`ProgramExtractor`、`ProgramLoader`、`ContainerService`。

此文件导入/转发：`ProgramExtractor`、`LoadedProgram`、`ProgramLoader`、`ExtractionOptions`、`ExtractionProgress`、`ExtractionResult`、`InspectionReport`、`PatchFailure`、`PatchInfo`、`ContainerService`。


### `extractor.py`

执行区块恢复、资源复制、取消与进度反馈，返回逐项失败。

#### `PatchEngine`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PatchEngine.decrypt_executable(executable: bytearray, patch: PatchRecord, file_offset: int, decrypt_resource: Callable[..., bool]) -> tuple[bool, str]` | 检查区块范围，调用注入的资源解码函数，返回 (成功, 原因)。 |

#### `ProgramExtractor`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ProgramExtractor.__init__(self, filesystem: FileSystem &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `ProgramExtractor.extract(self, program: LoadedProgram, options: ExtractionOptions &#124; None=None, progress: ProgressCallback &#124; None=None, cancelled: Callable[[], bool] &#124; None=None) -> ExtractionResult` | 逐项处理有效区块，反馈进度/取消，写主程序并返回含失败集合的结果。 |
| `ProgramExtractor._destination(program: LoadedProgram, options: ExtractionOptions) -> tuple[Path, Path]` | 优先 output_exe，其次 output_directory/默认目录，返回 (输出目录, 主程序位置)。 |
| `ProgramExtractor._apply(self, program: LoadedProgram, executable: bytearray, patch: PatchRecord, output: Path, copied: set[tuple[str, ...]]) -> tuple[bool, str]` | 按区块模式和文件名选择主程序文件偏移、RVA 或资源文件处理。 |
| `ProgramExtractor._apply_file(self, program: LoadedProgram, patch: PatchRecord, output: Path, copied: set[tuple[str, ...]]) -> tuple[bool, str]` | 校验资源相对路径，只先复制一次，再读取/校验/修改指定区块。 |


### `loader.py`

只读加载容器与主程序，统一解析器和错误码。

#### `LoadedProgram`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `source_path` | `Path` | `必填` | 输入源位置 |
| `source_directory` | `Path` | `必填` | 输入所在目录 |
| `source_name` | `str` | `必填` | 输入文件名 |
| `wrapper_size` | `int` | `必填` | 外壳文件区域 / Overlay 起点 |
| `wrapper_pe` | `PEFile` | `必填` | 外壳PE解析结果 |
| `stub` | `ContainerStub` | `必填` | 规范化容器配置 |
| `executable_bytes` | `bytes` | `必填` | 主程序只读字节 |
| `executable_pe` | `PEFile` | `必填` | 主程序PE解析结果 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `LoadedProgram.executable_version(self) -> str` | 只读属性：主程序PE位数描述；兼容名称不维护独立数据。 |
| `LoadedProgram.executable_size(self) -> int` | 只读属性：主程序字节数；兼容名称不维护独立数据。 |

#### `ProgramLoader`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ProgramLoader.__init__(self, filesystem: FileSystem &#124; None=None, pe_parser: type[PEParser]=PEParser, stub_parser: type[StubParser]=StubParser) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `ProgramLoader.load(self, executable_path: str &#124; Path) -> LoadedProgram` | 读取源、外壳、配置和主程序，返回只读 LoadedProgram；失败转换为 LoadError。 明确抛出：`LoadError`。 |
| `ProgramLoader._read_source(self, path: Path) -> bytes` | 检查源为文件并读取，读取失败映射为 FILE_NOT_FOUND。 明确抛出：`LoadError`。 |
| `ProgramLoader._parse_wrapper(self, raw: bytes) -> PEFile` | 要求外壳 PE32，并把结构失败映射为 WRAPPER_NOT_PE32。 明确抛出：`LoadError`。 |
| `ProgramLoader._parse_container(self, raw: bytes, wrapper_size: int) -> tuple[ContainerParseResult, ContainerStub &#124; None]` | 在 Overlay 起点调用 stub 解析器，返回状态和对象。 |
| `ProgramLoader._result_code(result: ContainerParseResult) -> ErrorCode` | 把容器结构、版本或 CRC 状态映射为稳定应用错误码。 |
| `ProgramLoader._read_executable(self, raw: bytes, source_directory: Path, wrapper_size: int, stub: ContainerStub) -> bytes` | 根据外置标志选择相对文件或对齐配置之后的内嵌主程序。 |
| `ProgramLoader._read_external_executable(self, source_directory: Path, stub: ContainerStub) -> bytes` | 规范化并检查配置的外置名称，然后读取文件。 明确抛出：`LoadError`。 |
| `ProgramLoader._parse_executable(self, executable: bytes) -> PEFile` | 依次尝试 PE32/PE64；都失败时返回主程序无效错误。 明确抛出：`LoadError`。 |


### `recovery.py`

应用层缓存和修复发布。

#### `RepairService`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `RepairService.__init__(self, compressor: Callable[[bytes], bytes] &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `RepairService.inspect(self, target: str &#124; Path) -> RepairInspection` | 只读解析真实输入并严格匹配构建配置，返回 PE 与配置检查结果。 |
| `RepairService.repair(self, target: str &#124; Path, output: str &#124; Path &#124; None=None, *, manifest: str &#124; Path &#124; None=None, work_dir: str &#124; Path &#124; None=None, aplib_dll: str &#124; Path &#124; None=None, backend: str='auto', search_start: int=0, search_count: int=1 << 32, overwrite: bool=False, progress: Progress &#124; None=None) -> RepairResult` | 分流静态或载荷策略，保护输入/输出身份，发布并重读全部事务文件。 明确抛出：`RecoveryError`。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_atomic_write(path: Path, data: bytes) -> None` | 同目录临时文件写入、flush/fsync 后 os.replace，finally 清理临时文件。 |
| `_json_bytes(value: dict) -> bytes` | 稳定缩进输出 ASCII 转义 JSON 与末尾换行，返回 UTF-8 字节。 |
| `load_payload_manifest(path: Path, original: bytes, profile) -> tuple[RecoveredPayload, ...]` | 验证清单身份和记录字段，读取载荷并重算摘要；相对路径以清单目录为基准。 明确抛出：`RecoveryError`。 |
| `save_payload_manifest(directory: Path, original: bytes, profile, payloads: tuple[RecoveredPayload, ...]) -> Path` | 先验证载荷，再写相对命名文件和 v2 清单，最后重读清单校验。 |
| `_aliases(path: Path, source: Path) -> bool` | 检查与源路径一致或 samefile 硬链接关系，供输出保护。 |
| `rollback_script(baseline_name: str, expected_sha256: str) -> bytes` | 生成可执行 POSIX 回滚文本，校验同目录基线摘要后恢复指定副本。 |


### `results.py`

不可变检查、选项、进度和结果 DTO，供不同表现层复用。

#### `ExtractionOptions`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `output_directory` | `Path &#124; None` | `None` | 生成内容所在目录 |
| `output_exe` | `Path &#124; None` | `None` | 显式主程序输出位置，优先于目录 |
| `output_name` | `str` | `'Recovered'` | 未指定输出时使用的默认子目录名 |

#### `ExtractionProgress`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `processed` | `int` | `必填` | 已处理区块数 |
| `total` | `int` | `必填` | 区块总数 |
| `patch_index` | `int &#124; None` | `None` | 当前区块索引 |
| `file_name` | `str` | `''` | 区块关联的相对文件名 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ExtractionProgress.fraction(self) -> float` | 返回 processed/total；total 为零时返回 1.0。 |

#### `PatchFailure`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `index` | `int` | `必填` | 区块或用例索引 |
| `reason` | `str` | `必填` | 失败原因 |

#### `PatchInfo`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `index` | `int` | `必填` | 区块或用例索引 |
| `file_name` | `str` | `必填` | 区块关联的相对文件名 |
| `position` | `int` | `必填` | 按区块模式解释的文件偏移或RVA |
| `length` | `int` | `必填` | 字节长度 |
| `signature1` | `int` | `必填` | 原始/还原签名 |
| `signature2` | `int` | `必填` | 对应加密/打包签名 |
| `reserve1` | `int` | `必填` | 格式保留字段 |
| `mode` | `PatchMode` | `必填` | 模式枚举或标志位 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PatchInfo.from_patch(cls, index: int, patch: PatchRecord) -> 'PatchInfo'` | 按索引复制规范化区块字段为不可变 PatchInfo。 |

#### `ExtractionResult`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `success` | `bool` | `必填` | 整体操作是否成功 |
| `output_directory` | `Path &#124; None` | `None` | 生成内容所在目录 |
| `failures` | `tuple[PatchFailure, ...]` | `()` | 逐项失败集合 |
| `error` | `str` | `''` | 操作级错误消息 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ExtractionResult.failed_indices(self) -> tuple[int, ...]` | 以元组返回失败区块索引，顺序与失败记录一致。 |
| `ExtractionResult.last_error(self) -> str` | 优先返回操作级 error，否则按每16项格式化失败索引。 |

#### `InspectionReport`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `source_path` | `Path` | `必填` | 输入源位置 |
| `wrapper_size` | `int` | `必填` | 外壳文件区域 / Overlay 起点 |
| `stub_level` | `str` | `必填` | 容器版本显示值 |
| `stub_size` | `int` | `必填` | 配置尺寸 |
| `stub_align_size` | `int` | `必填` | 配置对齐尺寸 |
| `mode_text` | `str` | `必填` | 模式显示文本 |
| `executable_version` | `str` | `必填` | 主程序PE位数描述 |
| `executable_size` | `int` | `必填` | 主程序字节数 |
| `patches` | `tuple[PatchInfo, ...]` | `必填` | 规范化补丁信息集合 |


### `service.py`

组合加载器与提取器，提供路径输入及已加载对象两类用例。

#### `ContainerService`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerService.__init__(self, filesystem: FileSystem &#124; None=None, loader: ProgramLoader &#124; None=None, extractor: ProgramExtractor &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `ContainerService.load(self, executable_path: str &#124; Path) -> LoadedProgram` | 将文件路径委托加载器，返回 LoadedProgram。 |
| `ContainerService.inspect(self, executable_path: str &#124; Path) -> InspectionReport` | 加载后返回不可变 InspectionReport，不写输出。 |
| `ContainerService.extract(self, executable_path: str &#124; Path, options: ExtractionOptions &#124; None=None, progress: ProgressCallback &#124; None=None) -> ExtractionResult` | 加载后执行提取，转交选项和进度回调。 |
| `ContainerService.extract_loaded(self, program: LoadedProgram, options: ExtractionOptions &#124; None=None, progress: ProgressCallback &#124; None=None) -> ExtractionResult` | 复用已加载对象，不重复读取容器配置，再执行提取。 |
| `ContainerService.inspect_loaded(self, program: LoadedProgram) -> InspectionReport` | 将已解析补丁转换为不可变信息，并组合检查报告。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_application.py tests/test_program.py tests/test_runtime_repair.py tests/test_native_repair.py -q
```

[返回项目总说明](../../README.md)
