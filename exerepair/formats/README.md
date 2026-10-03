# 字节格式：PE、容器与引擎

本目录以字节或流为输入，提供解析、地址映射与编码变换，不发布文件或弹出界面。

## 功能分组与边界

### 基础 PE

`PEFile.from_bytes()` 读取 DOS/NT 头、可选头和节表；可要求位数。
Overlay 为节原始文件数据末尾，`rva_to_foa()` 将 RVA 映射到文件偏移。
`PEParser.try_parse()` 为可失败的入口，格式不支持时返回 `None`。

### V1–V7 容器

`ContainerStub.parse()` 读取定长头、选择 `_Layout`、读取配置并校验解码 CRC。
V1 记录没有名称；后续布局按 CP932 解码带终止符的文件名，并规范化区块模式。
`decrypt_resource()` 需要可写缓冲区且至少四字节；先比较签名，再恢复签名并 XOR 剩余内容。
`packed_mode` 交换签名的方向，同一套算法处理两种方向。
版本尺寸、记录数与对齐见设计文档。

### Enigma PE 与引导

`PEImage` 额外保留构建所需头部、映像与节属性。
RVA 映射选择地址所属节，避免较早节的较大 RawSize 覆盖后续节。
`decode_enigma_bootstrap()` 查找具有唯一边界的解码层，歧义或结构变化返回格式错误。
`extract_enigma_engine()` 一次返回容器分析、原文件偏移和解压引擎字节。

### aPLib 与 BCJ

`aplib_decompress()` 按读字节、读位、gamma、literal 和回溯规则解码，
检查输入边界、回溯及最大输出长度。它不调用原生 DLL。
`bcj_transform()` 使用本配置引擎的 E8/E9 和间接调用规则；
接收 `encode` 方向，返回新字节，不修改输入缓冲区。

格式错误由 `PEFormatError` 或 `EnigmaFormatError` 表达；
容器解析用 `ContainerParseResult` 返回结构、版本或 CRC 失败。
输入的 RVA、文件偏移和引擎内偏移应分别传入，不混用。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`ImageSectionHeader`、`PEFile`、`PEFormatError`、`PEParser`、`ContainerStub`、`StubParser`。

此文件导入/转发：`ImageSectionHeader`、`PEFile`、`PEFormatError`、`PEParser`、`ContainerStub`、`StubParser`。


### `enigma.py`

构建使用的PE、引导解码、引擎提取、aPLib和BCJ纯字节实现。

#### `EnigmaFormatError`

#### `Section`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `name` | `str` | `必填` | 配置或节名称 |
| `virtual_size` | `int` | `必填` | 节逻辑内存大小 |
| `virtual_address` | `int` | `必填` | 节RVA起点 |
| `raw_size` | `int` | `必填` | 节原始数据大小 |
| `raw_offset` | `int` | `必填` | 节原始数据文件偏移 |
| `characteristics` | `int` | `必填` | 节属性位 |

#### `PEImage`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `machine` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `bitness` | `int` | `必填` | PE位数 |
| `timestamp` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `image_base` | `int` | `必填` | 映像首选基址 |
| `entry_rva` | `int` | `必填` | 映像入口RVA |
| `section_alignment` | `int` | `必填` | 内存布局对齐 |
| `file_alignment` | `int` | `必填` | 文件布局对齐 |
| `size_of_image` | `int` | `必填` | 内存映像对齐大小 |
| `size_of_headers` | `int` | `必填` | PE头总范围 |
| `subsystem` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `sections` | `tuple[Section, ...]` | `必填` | 节表结果 |
| `file_size` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PEImage.parse(cls, data: bytes &#124; bytearray &#124; memoryview) -> 'PEImage'` | 严格读取 PE32/PE64 映像信息和节范围，返回构建所需结构。 明确抛出：`EnigmaFormatError`。 |
| `PEImage.rva_to_offset(self, rva: int) -> int` | 按所属节与边界把 RVA 转换为文件偏移，无法映射时返回格式错误。 明确抛出：`EnigmaFormatError`。 |
| `PEImage.section_for_rva(self, rva: int) -> Section` | 按实际地址归属选择节，避免较早大 RawSize 抢占后续节。 明确抛出：`EnigmaFormatError`。 |

#### `DecoderLayer`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `relative_offset` | `int` | `必填` | 相对引导入口的字节位置 |
| `length` | `int` | `必填` | 字节长度 |
| `xor_byte` | `int` | `必填` | 层变换字节 |

#### `BootstrapAnalysis`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `entry_offset` | `int` | `必填` | 入口对应文件偏移 |
| `version` | `str` | `必填` | 版本标识 |
| `layers` | `tuple[DecoderLayer, ...]` | `必填` | 已识别解码层 |
| `decoded_image` | `bytes` | `必填` | 逐层解码后的独立映像 |

#### `EngineAnalysis`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `source_rva` | `int` | `必填` | 原映像内载荷地址 |
| `packed_size` | `int` | `必填` | 压缩容器字节容量 |
| `xor_key` | `int` | `必填` | 容器DWORD变换参数 |
| `unpacked_size` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `entry_rva` | `int` | `必填` | 映像入口RVA |
| `has_registration_api` | `bool` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |

#### `_AplibBits`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `_AplibBits.__init__(self, data: bytes &#124; bytearray) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `_AplibBits.byte(self) -> int` | 读取一个压缩字节，推进游标，截断时返回格式错误。 明确抛出：`EnigmaFormatError`。 |
| `_AplibBits.bit(self) -> int` | 从当前 tag 取位，必要时读取下一 tag 字节。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_decoder_candidates(image: bytearray, pe: PEImage, entry_offset: int, scan_end: int) -> list[tuple[int, DecoderLayer]]` | 在受限入口范围内查找符合指令/边界规则的 XOR 解码候选。 |
| `decode_enigma_bootstrap(data: bytes, pe: PEImage &#124; None=None) -> BootstrapAnalysis` | 复制输入并逐层解码唯一匹配的引导结构，返回解码图像与层参数。 明确抛出：`EnigmaFormatError`。 |
| `_aplib_gamma(bits: _AplibBits) -> int` | 解码 aPLib 变长整数，依赖有界字节/位读取。 |
| `aplib_decompress(data: bytes &#124; bytearray, max_output: int=128 * 1024 * 1024) -> bytes` | 执行该引导使用的 aPLib 解压，检查回溯和 max_output 上限，返回字节。 明确抛出：`EnigmaFormatError`。 |
| `extract_enigma_engine(target: bytes, pe: PEImage, bootstrap: BootstrapAnalysis) -> tuple[EngineAnalysis, int, bytes]` | 解析引导参数、定位并解码容器，返回 (分析, 文件偏移, 引擎字节)。 明确抛出：`EnigmaFormatError`。 |
| `inspect_enigma_engine(target: bytes, pe: PEImage, bootstrap: BootstrapAnalysis) -> EngineAnalysis` | 复用引擎提取，仅返回容器分析对象。 |
| `bcj_transform(data: bytes &#124; bytearray, *, encode: bool) -> bytes` | 按观察到的引擎规则 encode/decode 分支地址，返回新字节，不改输入。 |


### `pe.py`

基础PE头、节表、位数、Overlay和RVA映射。

#### `PEFormatError`

#### `ImageSectionHeader`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `name` | `str` | `必填` | 配置或节名称 |
| `virtual_size` | `int` | `必填` | 节逻辑内存大小 |
| `virtual_address` | `int` | `必填` | 节RVA起点 |
| `size_of_raw_data` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `pointer_to_raw_data` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `characteristics` | `int` | `必填` | 节属性位 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ImageSectionHeader.SectionName(self) -> str` | 只读属性：配置或节名称；兼容名称不维护独立数据。 |

#### `PEFile`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `bitness` | `int` | `必填` | PE位数 |
| `machine` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `pe_offset` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `optional_header_size` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `sections` | `tuple[ImageSectionHeader, ...]` | `必填` | 节表结果 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PEFile.from_bytes(cls, data: bytes &#124; bytearray &#124; memoryview, expected_bitness: int &#124; None=None) -> 'PEFile'` | 解析 PE 头与节表并按 expected_bitness 检查位数，返回 PEFile。 明确抛出：`PEFormatError`。 |
| `PEFile.Load(cls, data: bytes &#124; bytearray &#124; memoryview, expected_bitness: int &#124; None=None) -> 'PEFile'` | 兼容 from_bytes 的历史入口，使用相同字节和位数约束。 |
| `PEFile.overlay_data_file_offset(self) -> int` | 返回基础 PE 节原始数据末尾，供 Overlay 配置定位。 |
| `PEFile.OverlayDataFileOffset(self) -> int` | 只读属性：overlay_data_file_offset 当前状态；兼容名称不维护独立数据。 |
| `PEFile.ImageSectionHeaders(self) -> tuple[ImageSectionHeader, ...]` | 只读属性：节表结果；兼容名称不维护独立数据。 |
| `PEFile.rva_to_foa(self, rva: int) -> int` | 将基础 PE 的 RVA 映射为文件偏移，无节表或没有匹配区间时返回 `0`。 |
| `PEFile.RVAToFOA(self, rva: int) -> int` | 兼容方法，委托 `rva_to_foa`，参数和结果相同。 |
| `PEFile.__str__(self) -> str` | 返回本对象稳定显示文本，不改变内部状态。 |

#### `PEParser`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PEParser.parse(data: bytes &#124; bytearray &#124; memoryview, expected_bitness: int &#124; None=None) -> PEFile` | 具名解析器注入点，委托 PEFile.from_bytes。 |
| `PEParser.try_parse(data: bytes &#124; bytearray &#124; memoryview, expected_bitness: int &#124; None=None) -> PEFile &#124; None` | 尝试相同解析，预期格式失败返回 None。 |


### `stub.py`

V1–V7容器布局、记录、模式和签名/XOR变换。

#### `_Layout`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `version` | `ContainerVersion` | `必填` | 版本标识 |
| `argument_size` | `int` | `必填` | 配置参数字节数 |
| `alignment` | `int` | `必填` | 布局对齐大小 |
| `record_count` | `int` | `必填` | 布局记录数量 |
| `record_reader` | `'PatchRecordFormat'` | `必填` | 布局专用记录解析器 |
| `name_tail_size` | `int` | `0` | 末尾名称区域大小 |

#### `PatchRecordFormat`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `PatchRecordFormat.record_size(self) -> int` | 返回此布局单条记录的总字节数，用于定位下一记录。 |
| `PatchRecordFormat.parse(self, data: memoryview, offset: int) -> PatchRecord` | 协议签名：从 memoryview 的给定偏移解析规范化 PatchRecord。 |

#### `_V1Records`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `_V1Records.record_size(self) -> int` | 返回此布局单条记录的总字节数，用于定位下一记录。 |
| `_V1Records.parse(self, data: memoryview, offset: int) -> PatchRecord` | 读取 V1 四个 uint32 字段，规范化位置与两份签名。 |

#### `_NamedRecords`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `name_size` | `int` | `必填` | 此类型保存的格式/状态字段，具体解释见本节流程。 |
| `name_limit` | `int` | `-1` | 此类型保存的格式/状态字段，具体解释见本节流程。 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `_NamedRecords.record_size(self) -> int` | 返回此布局单条记录的总字节数，用于定位下一记录。 |
| `_NamedRecords.parse(self, data: memoryview, offset: int) -> PatchRecord` | 读取带名称布局、长度和签名，返回规范化补丁记录。 |

#### `ContainerStub`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ContainerStub.__init__(self, header: ContainerHeader, layout: _Layout) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `ContainerStub.level(self) -> ContainerVersion` | 只读属性：level 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.size(self) -> int` | 只读属性：字节大小；兼容名称不维护独立数据。 |
| `ContainerStub.align_size(self) -> int` | 只读属性：align_size 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.patches(self) -> tuple[PatchRecord, ...]` | 只读属性：规范化补丁信息集合；兼容名称不维护独立数据。 |
| `ContainerStub.executable_file_name(self) -> str` | 只读属性：executable_file_name 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.parse(cls, stream: BinaryIO &#124; bytes &#124; bytearray &#124; memoryview) -> tuple[ContainerParseResult, 'ContainerStub &#124; None']` | 校验头部长度和版本，读取定长配置、解码与 CRC，返回 (状态, 对象或 None)。 |
| `ContainerStub.create_factory(cls, stream: BinaryIO &#124; bytes &#124; bytearray &#124; memoryview) -> tuple[ContainerParseResult, 'ContainerStub &#124; None']` | 兼容工厂名称，委托 ContainerStub.parse。 |
| `ContainerStub.set_arguments(self, encrypted_arguments: bytes &#124; bytearray &#124; memoryview) -> ContainerParseResult` | 复制加密配置再 XOR，校验 CRC，提取模式与补丁集合。 |
| `ContainerStub._read_patch_records(self, arguments: memoryview) -> list[PatchRecord]` | 按布局记录数逐项解析，另处理主程序名称尾部。 |
| `ContainerStub._set_patch_modes(self) -> None` | 根据位置、名称与模式位分类 None_/ExecutableOnly/File/Memory。 |
| `ContainerStub.decrypt_resource(self, data: bytearray &#124; memoryview, key: int, signature1: int, signature2: int, packed_mode: bool=False) -> bool` | 检查可写范围和预期签名，再替换首 DWORD 与 XOR 其余字节，返回布尔值。 明确抛出：`TypeError`。 |
| `ContainerStub.Level(self) -> ContainerVersion` | 只读属性：level 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.Size(self) -> int` | 只读属性：字节大小；兼容名称不维护独立数据。 |
| `ContainerStub.AlignSize(self) -> int` | 只读属性：align_size 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.Config(self) -> ContainerConfig` | 只读属性：config 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.Patches(self) -> tuple[PatchRecord, ...]` | 只读属性：规范化补丁信息集合；兼容名称不维护独立数据。 |
| `ContainerStub.ExecutableFileName(self) -> str` | 只读属性：executable_file_name 当前状态；兼容名称不维护独立数据。 |
| `ContainerStub.SetArguments(self, encrypted_arguments: bytes &#124; bytearray &#124; memoryview) -> ContainerParseResult` | 兼容方法，委托 `set_arguments`，参数和结果相同。 |
| `ContainerStub.DecryptResource(self, data: bytearray &#124; memoryview, key: int, signature1: int, signature2: int, packed_mode: bool=False) -> bool` | 兼容方法，委托 `decrypt_resource`，参数和结果相同。 |

#### `StubParser`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `StubParser.parse(stream: BinaryIO &#124; bytes &#124; bytearray &#124; memoryview) -> tuple[ContainerParseResult, ContainerStub &#124; None]` | 可注入的具名容器解析入口，委托 ContainerStub.parse。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_read_exact(stream: BinaryIO, size: int) -> bytes` | 循环从流读取指定长度，遇到末尾停止，调用方校验是否读满。 |
| `_decode_name(data: bytes &#124; bytearray &#124; memoryview, limit: int=-1) -> str` | 在名称上限内找终止符，按 CP932 解码；空值或未终止返回空字符串。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_pe.py tests/test_pe_overlapping_raw.py tests/test_stub.py tests/test_runtime_repair.py -q
```

[返回项目总说明](../../README.md)
