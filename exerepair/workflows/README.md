# 修复参数、构建与二进制重放

本目录接收已确认身份的输入，生成候选、差异和文件级报告，不负责磁盘发布。

## 功能分组

### 配置匹配

`PROFILES` 管理识别信息与处理参数。`identify_profile()` 比较完整 SHA-256 和长度，
返回 `RepairProfile`、`NativeCallProfile` 或 `DiscCheckProfile`。
光盘检查配置仅按精确身份匹配；其他输入保留现有原生结构发现路径。
无法建立支持的配置时返回 `RecoveryError`。
配置中的 RVA、VM 索引、原字节和载荷摘要限定为该身份，不能自动移用到其他输入。

### 载荷构建

`validate_payloads()` 比较输入身份、载荷顺序、源范围、长度、CRC 和 SHA。
`patch_gate()` 对已验证 VM 记录改动并保留逐项记录；
`helper_and_data()` 创建位置无关复制代码和查找表，保留寄存器、标志和栈约定。
`build_capture_image()` 只生成供隔离捕获的中间字节，不发布为最终修复。
`build_repair()` 新增 `.repair`，保留原密文，重封装引擎，检查新增节和引擎重提取。

### 原生调用构建

`native_trampoline()` 对十字节保护条件做匹配，只有匹配时修改指定调用。
`_retire_dispatch_relocation()` 校验重定位块与目标记录；
`build_native_repair()` 追加 `.repair` 和 `.epack`，更新已验证引导参数，
并保持原容器和其他载荷字节不变。

### 光盘检查兼容

`disc_helper(profile, code_va, state_va, original_entry_va)` 返回
`(代码字节, 状态字节, 布局字典)`；保存通用寄存器和标志，以完整模块、
调用方及尾声保护条件控制单次修改，再还原 API 分派。
`build_disc_repair(original, profile) -> BuiltRepair` 只接收字节和
`DiscCheckProfile`，追加 RX `.repair` 与 RW `.rstate`，不引入新的 RWX 节，
不启动进程或依赖压缩器。签名、ASLR、字节、范围和节表不符时拒绝构建。
详见 [光盘检查流程](../../docs/DISC_CHECK_REPAIR.md)。

### 安装目录计划

`portable_setup.build_portable_setup(spec, image_base, code_va, module_size)`
返回不可变 `PortableSetupPlan(code, patches, guards, directory_object_va)`。
它校验完整调用形态、保护范围与重叠、地址、UTF-16 文本和 helper 容量，
不做文件或注册表 I/O，也不按配置名称分支。
`validate_directory_object(spec, image_size)` 检查目录字符串对象在原包装映像内，
不能将此处的映像大小替换为延迟加载模块的大小。

光盘构建器合并计划与现有调用点，拒绝冲突和旧式注册表 shim 混用；
worker 校验计划内所有原字节后才写入。布局报告中的
`portable_installation`、`portable_stub_offset`、`portable_directory_wstring_va`
描述是否启用、stub 位置及目录对象，不表示实际启动已经验证。

### 差异重放

`apply_binary_patch()` 接受 `seep.binary-patch.v2` JSON 对象：
基线/输出摘要与长度、编辑集合、Base64 替换字节和可选 `append` 模式。
检查输入身份、有效范围、重叠、替换长度和 append 必须位于文件末尾，
再检查最终长度与摘要。不读取参考 EXE，也不调用应用发布层。

## 输入、结果与失败

压缩器通过 `Callable[[bytes], bytes]` 注入；构建器返回 `BuiltRepair`。
PE 固定基址、ASLR、空白节表槽、原字节、引擎摘要或回封条件不符时停止。
报告的 `runtime_launch_verified` 是 `false`；它只包含构建与重放验证，
不代表已经启动目标程序。写盘、覆盖、源文件保护和回滚由应用层处理。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。


### `native_repair.py`

保护跳板、重定位退休、双节附加与原生构建验证。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `native_trampoline(profile: NativeCallProfile, image_base: int, helper_rva: int) -> bytes` | 检查十字节模式，只在匹配时改动指定CALL；恢复现场并重放调度MOV。 明确抛出：`RecoveryError`。 |
| `_retire_dispatch_relocation(engine: bytearray, pe: PEImage, profile) -> None` | 在实际重定位块中验证唯一目标记录并置为退休项。 明确抛出：`RecoveryError`。 |
| `build_native_repair(original: bytes, profile: NativeCallProfile, compressor: Callable[[bytes], bytes]) -> BuiltRepair` | 按精确配置附加跳板与新容器，修改引导参数并验证字节保留、往返与重放。 明确抛出：`RecoveryError`。 |


### `profiles.py`

管理修复识别信息与参数，按摘要及长度匹配。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `identify_profile(data: bytes) -> RepairProfile &#124; NativeCallProfile &#124; DiscCheckProfile` | 优先比较完整SHA256和长度，未命中时保留现有结构发现；无法建立配置时返回 RecoveryError。 |


### `repair.py`

载荷校验、VM编辑、helper/新节构建及通用v2差异重放。

#### `BuiltRepair`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `data` | `bytes` | `必填` | 字节内容 |
| `patch` | `dict` | `必填` | 可重放差异对象 |
| `report` | `dict` | `必填` | 构建/文件校验报告 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `sha256(data: bytes &#124; bytearray) -> str` | 返回输入字节的 SHA-256 小写十六进制摘要。 |
| `align(value: int, boundary: int) -> int` | 将数值向上对齐到指定边界的整数倍。 |
| `validate_payloads(original: bytes, profile: RepairProfile, payloads: tuple[RecoveredPayload, ...]) -> None` | 检查输入身份、集合顺序、源地址/节范围、大小、CRC与SHA256。 明确抛出：`RecoveryError`。 |
| `helper_and_data(payloads: tuple[RecoveredPayload, ...]) -> tuple[bytes, int]` | 构造保留GPR/EFLAGS的PIC复制helper和表，返回字节与RET8空操作位置。 明确抛出：`RecoveryError`。 |
| `_instruction(engine: bytes &#124; bytearray, profile: RepairProfile, index: int) -> int` | 检查VM表和索引，读取72字节指令记录起点并校验范围。 明确抛出：`RecoveryError`。 |
| `patch_gate(engine: bytes, profile: RepairProfile) -> tuple[bytearray, list[dict]]` | 只对已配置引擎执行门/谓词编辑，验证原字节及引用，返回缓冲区和编辑账本。 明确抛出：`RecoveryError`。 |
| `_encrypt_container(engine: bytes, analysis, compressor: Callable[[bytes], bytes]) -> bytes` | 压缩到原容量内、补齐并逐DWORD变换，超出容量返回错误。 明确抛出：`RecoveryError`。 |
| `build_capture_image(original: bytes, profile: RepairProfile, compressor: Callable[[bytes], bytes]) -> bytes` | 生成仅用于隔离捕获的门改动副本字节，不修改或发布输入。 明确抛出：`RecoveryError`。 |
| `apply_binary_patch(original: bytes, patch: dict) -> bytes` | 严格重放v2 replace/append记录，拒绝身份、范围、长度、重叠或摘要不符。 明确抛出：`RecoveryError`。 |
| `build_repair(original: bytes, profile: RepairProfile, payloads: tuple[RecoveredPayload, ...], compressor: Callable[[bytes], bytes]) -> BuiltRepair` | 校验载荷与PE约束，附加复制节并更新VM调用，验证引擎和完整差异。 明确抛出：`RecoveryError`。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_runtime_repair.py tests/test_native_repair.py tests/test_disc_repair.py tests/test_portable_setup.py -q
```

[返回项目总说明](../../README.md)
