# 外部适配器与计算后端

本目录连接纯用例与外部环境。文件系统、DLL、探测进程与 GPU 句柄的生命周期在此管理。

## 功能与环境

### 文件系统

`FileSystem` 是可替换协议，`LocalFileSystem` 使用 pathlib/shutil 实现字节读取、
目录创建、复制、文件尺寸和局部读写。局部写入仅替换指定区段，不重建其他字节。
低层写入可以覆盖已有文件；输入别名保护由修复应用层负责。

### aPLib 压缩器

`resolve_library()` 依次使用显式参数、`EXEREPAIR_APLIB_DLL`、完整内置发行包。
内置包先比对 SHA-256，再按当前 Python 位数提取唯一 DLL 到临时缓存。
`AplibCompressor` 延迟加载 Windows DLL，绑定容量和压缩函数，检查缓冲区上限。
正常包导入和只读识别不会加载 DLL。

### CPU / OpenCL 筛选

`cpu_filter.py` 用 NumPy/Numba 实现固定输入 MD5、RC4、aPLib 前缀规则及并行扫描。
`opencl_filter.py` 用 ctypes 绑定 OpenCL 1.2，编译 `component_prefix.cl`，返回 uint8 候选位图。
OpenCL 输入前缀为 16 字节，密文至少 128 字节；扫描区间有 32 位域和单批上限。
工作组大小由设备/内核信息决定。输入相同时复用缓冲区，变化时重新上传；
输出容量不足时增长并释放旧缓冲区，`close()` 反序释放自己持有的全部句柄。

### 捕获与恢复

`capture_context()` 只为已验证载荷配置创建自己的临时探测副本及 Frida 会话。
`runtime_capture.js` 处理指定单步异常、采集描述符、停驻线程；
RPC `take()` 取出一次上下文并清除 JS 保存的引用。
Python 的所有退出路径清理自身进程、线程句柄、会话和临时目录。

`recover_payloads()` 验证上下文身份与模式，选择后端，跑合成 CPU/GPU 对照，
按最多 `2^20` 个候选分批，结构筛选后执行全量 CRC/SHA-256。
全部载荷匹配后返回不可变载荷元组；无匹配返回 `RecoveryError`。
搜索游标记录完成区间和输入身份，不记录候选分量或派生密钥。

## 附属文件

| 文件 | 接口 / 行为 |
| --- | --- |
| `component_prefix.cl` | MD5/RC4 流和 aPLib 结构筛选；`filter` 是设备入口，每个候选输出一个标志 |
| `runtime_capture.js` | `guest` 定位来宾状态；`handled` 更新异常标志；异常回调与 `rpc.exports.take` 组成捕获接口 |
| `native` | 完整 aPLib 发行包与许可说明，见该目录 README |

CPU 与 GPU 位图只筛选结构候选，不是最终成功条件。显式 GPU 失败不会静默换 CPU。
运行时捕获与 GPU 不在普通单元测试中自动启动；合成适配器测试与真实运行验证分开记录。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`FileSystem`、`LocalFileSystem`。

此文件导入/转发：`FileSystem`、`LocalFileSystem`。


### `aplib.py`

选择并延迟绑定匹配架构 DLL，提供受限的原生压缩回调。

#### `AplibCompressor`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `AplibCompressor.__init__(self, path: str &#124; Path &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 明确抛出：`RecoveryError`。 |
| `AplibCompressor.__call__(self, data: bytes) -> bytes` | 接收非空且不超过 128 MiB 的字节，检查分配上限与压缩返回长度，返回压缩字节。 明确抛出：`RecoveryError`。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `resolve_library(path: str &#124; Path &#124; None=None) -> Path` | 从参数、环境变量或匹配架构发行包解析 DLL；返回缓存库路径。 明确抛出：`RecoveryError`。 |


### `component_recovery.py`

合成向量验证、上下文校验、后端选择、有界恢复与搜索游标。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_primitives()` | 延迟导入 NumPy/Numba，限制 CPU 线程，验证 MD5/RC4 合成向量并返回算法函数。 明确抛出：`RecoveryError`。 |
| `verify_filter(engine, compressor) -> dict` | 对独立低位/高位合成区间比较 CPU/GPU 标志并验证唯一完整 CRC 候选。 明确抛出：`RecoveryError`。 |
| `recover_payloads(original: bytes, profile, context: dict, *, backend: str, start: int, count: int, progress: Callable[[str], None], work_dir: Path) -> tuple[RecoveredPayload, ...]` | 按给定范围恢复所有载荷，重算完整 CRC/SHA；保存区间游标并在 finally 关闭 GPU。 明确抛出：`RecoveryError`。 |


### `cpu_filter.py`

Numba CPU 算法与结构筛选；返回候选标志，不代替完整载荷校验。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `md5_u32(value)` | 将 32 位值的 LE32 表示映射为 16 字节 MD5；为合成验证和筛选提供固定输入算法。 |
| `rc4(data, key)` | 按给定字节密钥处理输入数组，返回独立结果，用于合成及完整载荷校验。 |
| `bit(data, pos, tag, left)` | 从 tag 状态读取一位，返回读取值与更新后的游标/位状态。 |
| `gamma(data, pos, tag, left)` | 依格式连续读取位编码整数及更新状态，供 aPLib 前缀判断使用。 |
| `valid_prefix(data, max_output)` | 按有界 aPLib 流规则判断前缀候选；它不输出完整游戏载荷。 |
| `scan(prefix, cipher, start, count, max_output)` | 在起点与候选数定义的区间扫描，返回每个候选的 uint8 结构标志。 |


### `filesystem.py`

抽象文件操作，并用本地字节 I/O 实现协议。

#### `FileSystem`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `FileSystem.is_file(self, path: Path) -> bool` | 判断路径是否为普通文件，返回布尔值。 |
| `FileSystem.read_bytes(self, path: Path) -> bytes` | 读取完整文件字节；本地实现通过 pathlib 执行，I/O 错误向上传播。 |
| `FileSystem.make_directory(self, path: Path) -> None` | 创建目标目录及父目录，已存在目录可复用。 |
| `FileSystem.copy_file(self, source: Path, destination: Path) -> None` | 复制源文件到目标，并准备目标父目录。 |
| `FileSystem.file_size(self, path: Path) -> int` | 返回 stat 中的文件字节数。 |
| `FileSystem.read_range(self, path: Path, offset: int, length: int) -> bytes` | 定位到给定文件偏移，读取至多指定长度的字节。 |
| `FileSystem.write_bytes(self, path: Path, data: bytes &#124; bytearray) -> None` | 写完整字节并准备父目录；可替换原目标内容。 |
| `FileSystem.write_range(self, path: Path, offset: int, data: bytes &#124; bytearray) -> None` | 以读写方式打开现有文件，仅写给定偏移区段。 |

#### `LocalFileSystem`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `LocalFileSystem.is_file(self, path: Path) -> bool` | 判断路径是否为普通文件，返回布尔值。 |
| `LocalFileSystem.read_bytes(self, path: Path) -> bytes` | 读取完整文件字节；本地实现通过 pathlib 执行，I/O 错误向上传播。 |
| `LocalFileSystem.make_directory(self, path: Path) -> None` | 创建目标目录及父目录，已存在目录可复用。 |
| `LocalFileSystem.copy_file(self, source: Path, destination: Path) -> None` | 复制源文件到目标，并准备目标父目录。 |
| `LocalFileSystem.file_size(self, path: Path) -> int` | 返回 stat 中的文件字节数。 |
| `LocalFileSystem.read_range(self, path: Path, offset: int, length: int) -> bytes` | 定位到给定文件偏移，读取至多指定长度的字节。 |
| `LocalFileSystem.write_bytes(self, path: Path, data: bytes &#124; bytearray) -> None` | 写完整字节并准备父目录；可替换原目标内容。 |
| `LocalFileSystem.write_range(self, path: Path, offset: int, data: bytes &#124; bytearray) -> None` | 以读写方式打开现有文件，仅写给定偏移区段。 |


### `opencl_filter.py`

OpenCL 1.2 GPU 筛选适配器，管理设备、缓冲区和句柄生命周期。

#### `OpenCLFilter`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `OpenCLFilter.__init__(self)` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `OpenCLFilter._initialize(self)` | 枚举 GPU，创建上下文/队列，编译内核并读取工作组限制。 明确抛出：`RuntimeError`。 |
| `OpenCLFilter._bind(self)` | 设置所使用 OpenCL C 函数的 ctypes ABI 与类型。 |
| `OpenCLFilter.check(status)` | 非零 API 状态转为 RuntimeError；零状态不返回数据。 明确抛出：`RuntimeError`。 |
| `OpenCLFilter.info(function, obj, field)` | 先查询长度再读取设备/对象字符串，返回 UTF-8 文本。 |
| `OpenCLFilter._buffer(self, flags, size, data=None)` | 创建设备缓冲区并登记释放函数，可用主机数组初始化。 |
| `OpenCLFilter._inputs(self, prefix, cipher)` | 首次分配输入缓冲区；输入变化时上传，否则复用已缓存内容。 |
| `OpenCLFilter.scan(self, prefix, cipher, start, count, max_output)` | 验证一维前缀/密文和区间，复用缓冲区、执行内核并读取候选位图。 明确抛出：`RuntimeError`、`ValueError`。 |
| `OpenCLFilter.close(self)` | 反序释放拥有的对象，清空输入引用及输出容量；关闭后不能扫描。 |
| `OpenCLFilter.__enter__(self)` | 返回当前实例，供上下文管理器使用。 |
| `OpenCLFilter.__exit__(self, *_)` | 离开上下文时释放设备资源；不吞掉调用中的异常。 |


### `runtime_capture.py`

拥有并清理隔离探测进程，读取一次描述符上下文。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `capture_context(original, game_root, profile, compressor, work_dir, timeout=60, progress=None) -> dict` | 创建和拥有临时探测进程；在超时内获取上下文，所有退出路径清理自身资源。 明确抛出：`RecoveryError`、`ctypes.WinError`。 |


## 子目录

- [native](native/README.md)：详细模块与功能说明。

## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_opencl_filter.py tests/test_runtime_repair.py -q
```

[返回项目总说明](../../README.md)
