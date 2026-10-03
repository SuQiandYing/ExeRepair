# 领域契约：模型、枚举、错误与路径

本目录提供内外层共用的数据和错误契约，不执行文件读写、设备枚举或界面操作。

## 功能分组

- `models.py`：容器模式位、区块模式、版本、解析结果、头部、配置与补丁记录。
- `errors.py`：稳定的 `ErrorCode` 以及带原因的加载/提取错误。
- `paths.py`：解析容器中的 Windows 相对文件名，拒绝根路径、盘符和 `..`。
- `recovery.py`：两类构建配置、载荷、检查结果和发布结果。

## 关键字段含义

`PatchRecord.position` 按 `mode` 解释为文件偏移或 RVA，不是通用写入地址。
`ContainerFlags` 是位组合，格式化时未知位以数值保留。零值也显示数值。
`PayloadSpec.source_rva` 与 `source_offset` 分别是映像地址与文件地址；
`size`、`crc32`、`clear_sha256` 是恢复载荷需匹配的条件。
`NativeCallProfile` 不启用载荷恢复；其 `payloads` 固定为空，不作为初始化参数。
`RecoveredPayload.data` 不进入默认 repr，减少无意输出载荷内容。

模型中的大写属性是兼容接口，读取对应的小写字段，不添加另一套状态。
`safe_relative_parts()` 返回规范化路径部件或 `None`；
`join_relative()` 只是按策略拼接，不证明文件存在，也不是符号链接安全检查。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`ContainerConfig`、`ErrorCode`、`ContainerFlags`、`ContainerHeader`、`ContainerVersion`、`PatchRecord`、`PatchMode`、`ExtractError`、`LoadError`、`OperationError`、`ContainerParseResult`、`format_container_flags`。

此文件导入/转发：`ContainerConfig`、`ContainerFlags`、`ContainerHeader`、`ContainerVersion`、`PatchRecord`、`PatchMode`、`ContainerParseResult`、`format_container_flags`、`ErrorCode`、`ExtractError`、`LoadError`、`OperationError`。


### `errors.py`

定义稳定错误码、显示消息与原始异常原因。

#### `ErrorCode`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `FILE_NOT_FOUND` | `'file_not_found'` |
| `WRAPPER_NOT_PE32` | `'wrapper_not_pe32'` |
| `STUB_INVALID` | `'stub_invalid'` |
| `STUB_UNKNOWN_VERSION` | `'stub_unknown_version'` |
| `STUB_HASH_INVALID` | `'stub_hash_invalid'` |
| `EXECUTABLE_NOT_FOUND` | `'executable_not_found'` |
| `EXECUTABLE_INVALID` | `'executable_invalid'` |
| `NOT_LOADED` | `'not_loaded'` |
| `OUTPUT_ERROR` | `'output_error'` |

#### `OperationError`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `OperationError.__init__(self, code: ErrorCode, message: str, cause: Exception &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `OperationError.__str__(self) -> str` | 返回本对象稳定显示文本，不改变内部状态。 |

#### `LoadError`

#### `ExtractError`


### `models.py`

定义容器枚举、头部、配置和规范化区块记录。

#### `ContainerFlags`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `UseCommandLineShortPath` | `1` |
| `UseDefaultDisplaySetting` | `2` |
| `AutoVerify` | `4` |
| `UseExecutableFileNameArgument` | `8` |
| `AllowMultiProcess` | `16` |
| `UCScidChargeDialog` | `32` |
| `ExecutableFileNotPack` | `64` |
| `ShowSoftDCDialog` | `128` |
| `UseTempPath` | `256` |
| `UseLockFile` | `512` |
| `UCDialogVersion3` | `1024` |
| `USE_COMMAND_LINE_SHORT_PATH` | `UseCommandLineShortPath` |
| `USE_DEFAULT_DISPLAY_SETTING` | `UseDefaultDisplaySetting` |
| `AUTO_VERIFY` | `AutoVerify` |
| `USE_EXECUTABLE_FILE_NAME_ARGUMENT` | `UseExecutableFileNameArgument` |
| `ALLOW_MULTI_PROCESS` | `AllowMultiProcess` |
| `UC_SCID_CHARGE_DIALOG` | `UCScidChargeDialog` |
| `EXECUTABLE_FILE_NOT_PACK` | `ExecutableFileNotPack` |
| `SHOW_SOFT_DC_DIALOG` | `ShowSoftDCDialog` |
| `USE_TEMP_PATH` | `UseTempPath` |
| `USE_LOCK_FILE` | `UseLockFile` |
| `UC_DIALOG_VERSION_3` | `UCDialogVersion3` |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerFlags.__str__(self) -> str` | 返回本对象稳定显示文本，不改变内部状态。 |

#### `PatchMode`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `None_` | `0` |
| `ExecutableOnly` | `1` |
| `File` | `2` |
| `Memory` | `3` |
| `NONE` | `None_` |
| `EXECUTABLE_ONLY` | `ExecutableOnly` |
| `FILE` | `File` |
| `MEMORY` | `Memory` |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PatchMode.__str__(self) -> str` | 返回本对象稳定显示文本，不改变内部状态。 |

#### `ContainerVersion`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `V1` | `0` |
| `V2` | `1` |
| `V3` | `2` |
| `V4` | `3` |
| `V5` | `4` |
| `V6` | `5` |
| `V7` | `6` |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerVersion.__str__(self) -> str` | 返回本对象稳定显示文本，不改变内部状态。 |

#### `ContainerParseResult`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `Successed` | `0` |
| `StubInvalid` | `3221225472` |
| `StubUnknowVersion` | `3221225473` |
| `StubHashInvalid` | `3221225474` |
| `SUCCEEDED` | `Successed` |
| `STUB_INVALID` | `StubInvalid` |
| `STUB_UNKNOWN_VERSION` | `StubUnknowVersion` |
| `STUB_HASH_INVALID` | `StubHashInvalid` |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerParseResult.succeeded(self) -> bool` | 判断当前解析状态是否为 Successed。 |
| `ContainerParseResult.error_message(self) -> str` | 将解析失败状态映射到稳定的短消息，成功返回空字符串。 |
| `ContainerParseResult.Successed_(self) -> bool` | 兼容历史可调用名称，返回 succeeded 属性。 |

#### `ContainerHeader`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `version` | `int` | `必填` | 版本标识 |
| `hash` | `int` | `必填` | 配置校验值 |
| `key` | `int` | `必填` | 格式变换参数 |
| `reserve1` | `int` | `0` | 格式保留字段 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerHeader.Version(self) -> int` | 只读属性：版本标识；兼容名称不维护独立数据。 |
| `ContainerHeader.Hash(self) -> int` | 只读属性：配置校验值；兼容名称不维护独立数据。 |
| `ContainerHeader.Key(self) -> int` | 只读属性：格式变换参数；兼容名称不维护独立数据。 |

#### `ContainerConfig`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `mode` | `ContainerFlags` | `必填` | 模式枚举或标志位 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerConfig.Mode(self) -> ContainerFlags` | 只读属性：模式枚举或标志位；兼容名称不维护独立数据。 |

#### `PatchRecord`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `file_name` | `str` | `''` | 区块关联的相对文件名 |
| `position` | `int` | `0` | 按区块模式解释的文件偏移或RVA |
| `length` | `int` | `0` | 字节长度 |
| `signature1` | `int` | `0` | 原始/还原签名 |
| `signature2` | `int` | `0` | 对应加密/打包签名 |
| `reserve1` | `int` | `0` | 格式保留字段 |
| `mode` | `PatchMode` | `PatchMode.None_` | 模式枚举或标志位 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PatchRecord.FileName(self) -> str` | 只读属性：区块关联的相对文件名；兼容名称不维护独立数据。 |
| `PatchRecord.Position(self) -> int` | 只读属性：按区块模式解释的文件偏移或RVA；兼容名称不维护独立数据。 |
| `PatchRecord.Length(self) -> int` | 只读属性：字节长度；兼容名称不维护独立数据。 |
| `PatchRecord.Signature1(self) -> int` | 只读属性：原始/还原签名；兼容名称不维护独立数据。 |
| `PatchRecord.Signature2(self) -> int` | 只读属性：对应加密/打包签名；兼容名称不维护独立数据。 |
| `PatchRecord.Reserve1(self) -> int` | 只读属性：格式保留字段；兼容名称不维护独立数据。 |
| `PatchRecord.Mode(self) -> PatchMode` | 只读属性：模式枚举或标志位；兼容名称不维护独立数据。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `format_container_flags(value: ContainerFlags &#124; int) -> str` | 按稳定顺序格式化已知标志；零或未知位保留数字显示。 |


### `paths.py`

校验容器相对路径并与调用者提供的基础目录拼接。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `safe_relative_parts(file_name: str) -> tuple[str, ...] &#124; None` | 解析 Windows 相对文件名，拒绝空值、盘符、绝对根及上级目录，返回部件或 None。 |
| `join_relative(base: Path, file_name: str) -> Path &#124; None` | 复用相对路径策略，按部件拼接到 base；无效名称返回 None。 |


### `recovery.py`

不可变配置、载荷、检查及发布结果契约。

#### `RecoveryError`

#### `PayloadSpec`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `source_rva` | `int` | `必填` | 原映像内载荷地址 |
| `source_offset` | `int` | `必填` | 原文件载荷偏移 |
| `size` | `int` | `必填` | 字节大小 |
| `flags` | `int` | `必填` | 载荷处理标志 |
| `crc32` | `int` | `必填` | 完整恢复字节预期CRC |
| `clear_sha256` | `str` | `必填` | 完整恢复字节预期SHA256 |

#### `RepairProfile`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `name` | `str` | `必填` | 配置或节名称 |
| `baseline_sha256` | `str` | `必填` | 精确输入SHA256 |
| `baseline_size` | `int` | `必填` | 精确输入长度 |
| `engine_sha256` | `str` | `必填` | 解压引擎预期SHA256 |
| `engine_base_delta` | `int` | `必填` | 引擎相对主映像基址偏移 |
| `vm_table_offset` | `int` | `必填` | 引擎内VM表位置 |
| `vm_table_count` | `int` | `必填` | VM表项总数 |
| `payloads` | `tuple[PayloadSpec, ...]` | `必填` | 规定顺序的载荷规格集合 |
| `dialog_index` | `int` | `9950` | 已验证分支VM索引 |
| `dialog_destination` | `int` | `9954` | 预期分支目标索引 |
| `predicate_index` | `int` | `19155` | 原谓词VM索引 |
| `true_index` | `int` | `339` | 复用真值指令索引 |
| `ksa_index` | `int` | `18591` | 原KSA调用索引 |
| `prga_index` | `int` | `18598` | 原PRGA调用索引 |
| `ksa_operand` | `int` | `420004` | KSA预期原操作数 |
| `prga_operand` | `int` | `419808` | PRGA预期原操作数 |

#### `NativeCallProfile`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `name` | `str` | `必填` | 配置或节名称 |
| `baseline_sha256` | `str` | `必填` | 精确输入SHA256 |
| `baseline_size` | `int` | `必填` | 精确输入长度 |
| `engine_sha256` | `str` | `必填` | 解压引擎预期SHA256 |
| `engine_base_delta` | `int` | `必填` | 引擎相对主映像基址偏移 |
| `dispatch_rva` | `int` | `必填` | 原引擎调度入口位置 |
| `dispatch_global_rva` | `int` | `必填` | 迁移MOV引用的全局位置 |
| `relocation_offset` | `int` | `必填` | 需验证并退休的引擎重定位记录位置 |
| `guard_rva` | `int` | `必填` | 十字节运行保护条件起点 |
| `call_rva` | `int` | `必填` | 目标原生调用地址 |
| `guard_bytes` | `bytes` | `必填` | 完整预期保护模式 |
| `bootstrap_size_offsets` | `tuple[int, int]` | `必填` | 两组引导容量参数相对位置 |
| `bootstrap_source_offsets` | `tuple[int, int]` | `必填` | 两组引导源RVA参数相对位置 |
| `payloads` | `tuple[PayloadSpec, ...]` | `field(default=(), init=False)` | 规定顺序的载荷规格集合 |

#### `RecoveredPayload`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `spec` | `PayloadSpec` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `data` | `bytes` | `field(repr=False)` | 字节内容 |

#### `RepairInspection`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `source_path` | `Path` | `必填` | 输入源位置 |
| `profile` | `RepairProfile &#124; NativeCallProfile` | `必填` | 已匹配构建配置 |
| `entry_rva` | `int` | `必填` | 映像入口RVA |
| `image_base` | `int` | `必填` | 映像首选基址 |
| `size_of_image` | `int` | `必填` | 内存映像对齐大小 |
| `section_count` | `int` | `必填` | 节数量 |

#### `RepairResult`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `output_path` | `Path` | `必填` | 生成EXE位置 |
| `output_sha256` | `str` | `必填` | 生成内容摘要 |
| `diff_path` | `Path` | `必填` | 差异账本位置 |
| `verification_path` | `Path` | `必填` | 验证账本位置 |
| `rollback_path` | `Path` | `必填` | 回滚脚本位置 |
| `recovered_payload_count` | `int` | `必填` | 已校验恢复载荷数量 |
| `original_unchanged` | `bool` | `必填` | 发布前后输入身份校验结果 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_stub.py tests/test_application.py tests/test_runtime_repair.py tests/test_architecture.py -q
```

[返回项目总说明](../../README.md)
