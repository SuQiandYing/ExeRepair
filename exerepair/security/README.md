# CRC32、序列生成与 XOR

本目录提供确定性的兼容算法，不访问文件、目标进程或网络。

## 功能与输入输出

- `checksum.py` 构建 CRC 表，`crc32()` 接收 bytes、bytearray 或 memoryview，返回 32 位整数。
- `CRC32.hash()`、`CRC32.Hash()` 都委托同一个实现，属于兼容命名。
- `RandomV1` 保存 521 个 32 位状态字，初始化种子按 uint32 截断，再按既定步骤展开和预热。
- `move_next()` 返回下一个状态字；遍历完状态时执行 `_transform()`。
- `xor_in_place()` 将每个字节与下一状态字的低八位 XOR，原地修改可写缓冲区。

对同一长度的数据使用相同 key 再调用一次 XOR 会恢复原字节。
只读 memoryview 会抛出 `TypeError`。该序列是格式兼容实现，不是密码学随机源，
CRC 是完整性检测值，不作为身份认证；修复身份使用完整 SHA-256。

测试使用固定 CRC 向量、已有序列参考值和 XOR 往返。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`CRC32`、`RandomV1`、`crc32`、`xor_in_place`。

此文件导入/转发：`CRC32`、`crc32`、`RandomV1`、`xor_in_place`。


### `checksum.py`

确定性 CRC32 表与兼容方法。

#### `CRC32`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `CRC32.hash(data: bytes &#124; bytearray &#124; memoryview) -> int` | 兼容 CRC 类方法，委托 crc32。 |
| `CRC32.Hash(data: bytes &#124; bytearray &#124; memoryview) -> int` | 大写兼容名称，委托相同 CRC 算法。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_build_crc_table() -> tuple[int, ...]` | 构建 CRC 查表元组，导入时供校验函数复用。 |
| `crc32(data: bytes &#124; bytearray &#124; memoryview) -> int` | 计算项目格式所需 32 位 CRC，返回整数，不修改输入。 |


### `stream.py`

521 状态字序列生成器与可逆原地 XOR。

#### `RandomV1`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `RandomV1.__init__(self, seed: int=0) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `RandomV1._initialize(self, seed: int) -> None` | 从截断种子展开521个状态字，执行三轮变换后设置游标。 |
| `RandomV1._transform(self) -> None` | 按固定相对位置 XOR 更新状态表，保留已有兼容序列。 |
| `RandomV1.move_next(self) -> int` | 推进游标，必要时变换状态表，返回下一个32位状态字。 |
| `RandomV1.MoveNext(self) -> int` | 历史大写接口，委托 move_next。 |

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `xor_in_place(data: bytearray &#124; memoryview, key: int) -> None` | 以key初始化序列，用状态低8位逐字节XOR；要求可写输入。 明确抛出：`TypeError`。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_crypto.py tests/test_stub.py -q
```

[返回项目总说明](../../README.md)
