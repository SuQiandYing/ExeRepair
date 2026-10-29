# Enigma 静态恢复与运行时边界

ExeRepair 提供独立的 Enigma 配置解析、加密 section 恢复、section salt 搜索和 EVB 文件提取流程。该流程读取输入副本，不启动目标程序，也不把 section salt、密钥前缀或其他派生值写入日志、清单和输出目录。

## 功能组成

| 模块 | 职责 |
| --- | --- |
| `exerepair/formats/enigma_common.py` | 有界 LZ 解压、LZ 前缀筛选、E8/E9/FF25 分支恢复、RC4、section key、IDEA CBC 和 CRC32 |
| `exerepair/formats/enigma_unpack.py` | 元数据解密、描述符解析、entry patch、section 解密、CRC/LZ 校验、import record 和安全 section 恢复 |
| `exerepair/adapters/enigma_search.py` | OpenCL、Numba CPU 和有界精确候选筛选，统一执行完整 section 校验 |
| `exerepair/formats/evb.py` | EVB v1/v3 目录定位、路径检查、明文/压缩文件恢复 |
| `exerepair/application/enigma.py` | `EnigmaService` 检查、恢复、进度通知和输出目录发布 |
| `exerepair/cli.py` | `--enigma` 命令行入口和参数校验 |

已有的 `exerepair/formats/enigma.py` 负责 PE、Enigma 引导层、aPLib 和引擎容器识别；上述模块负责配置、section 和 EVB 数据处理。

## 输入与准备

静态恢复需要调用方提供经过入口分析确认的元数据 RVA。`--enigma-metadata-rva` 是恢复模式的必填参数。`--enigma --inspect` 可以先只解析 PE；提供元数据 RVA 后会继续验证配置描述符。

输入由 `PEImage.parse()` 严格检查 DOS/NT 头、位数、节表、Raw 范围和 RVA 映射。元数据解码按固定顺序尝试两种 MD5 派生 key，并验证：

1. 元数据密文 MD5；
2. RC4 与有界 LZ 解码；
3. 明文尾部 MD5；
4. 描述符数量、长度、RVA、CRC 和 serialized table 范围。

## 恢复流程

`EnigmaService.recover()` 执行以下步骤：

1. 读取并解析 PE；
2. 解析 Enigma 配置和可选 Loader context；
3. 读取 enabled section，并应用唯一 entry patch；
4. 如果没有传入 salt，先检查未加盐状态；
5. 对未知 salt 使用 `auto`、OpenCL、Numba CPU 或有界精确候选筛选；
6. 对每个候选执行所有 section 的 RC4、CRC32、LZ 和长度校验；
7. 恢复 section 字节，并在 context 足够时提取 EVB 虚拟文件；
8. 将恢复节写入 `output_directory/sections/`，将 EVB 相对路径写到同一输出目录。

命令行示例：

```powershell
# 只读 PE 和配置检查
python -m exerepair TARGET.exe --enigma --inspect --enigma-metadata-rva 0x2040

# 自动选择搜索适配器
python -m exerepair TARGET.exe --enigma --enigma-metadata-rva 0x2040 `
  --backend auto --search-start 0 --search-count 0x100000 `
  --output .\output\TARGET_enigma

# 已知 salt 时跳过候选搜索
python -m exerepair TARGET.exe --enigma --enigma-metadata-rva 0x2040 `
  --enigma-salt 0x12345678 --output .\output\TARGET_enigma
```

`output_directory` 必须是不存在的目录，避免把一次恢复的文件与另一份结果混合。服务保留输入文件不变；CLI 只显示“已恢复”或“未加密”，不显示 salt 数值。

## EVB 与路径安全

EVB v1 的目录记录与文件数据交错，v3 先解密并解压目录，再读取压缩索引和独立 LZ block。提取器限制最大展开尺寸、文件数量、子节点数量和记录边界，并拒绝绝对路径、`..`、设备名、通配符、环境变量样式路径及尾随点/空格路径。输出路径在写出前再次检查重复项。

## 公开接口

```python
from pathlib import Path
from exerepair.api import EnigmaService

METADATA_RVA = 0x2040  # 替换为目标样本实际的元数据 RVA
service = EnigmaService()
inspection = service.inspect("TARGET.exe", metadata_rva=METADATA_RVA)
result = service.recover(
    inspection.source_path,
    metadata_rva=inspection.metadata_rva,
    backend="auto",
    output_directory=Path("TARGET_enigma"),
)
print(len(result.recovered_sections), len(result.evb_files))
```

格式层还公开 `parse_configuration()`、`stored_sections()`、`decode_section()`、`recover_sections()`、`restore_recovered_sections()`、`parse_import_records()` 和 `extract_evb()`。这些函数不创建文件，不启动进程；应用服务负责目录发布。

## 当前边界

以下功能当前没有纳入静态恢复流程：

- Loader 入口的静态 x86 指令跟踪和元数据/Loader 自动定位；
- VM token、handler、模板入口和完整静态反虚拟化；
- x86 IR、寄存器/标志语义和原生代码生成；
- 原始 IAT、TLS、重定位和 Loader 启动路径重建；
- 删除 Loader 后生成独立可运行 PE 的完整重建流程；
- runtime DLL 单独提取模式和 CUDA/WGPU 构建链。

因此 `sections/` 中的恢复字节和 EVB 文件是静态恢复产物；它们不自动等价于已经去壳且可直接运行的 EXE。现有 `RepairService` 的已验证 profile 流程继续使用自己的清单、捕获和事务发布契约，`--enigma` 是独立的静态检查/恢复入口。

## 验证

```powershell
python -m pytest tests/test_enigma_recovery.py -q
python -m pytest -q
python -m ruff check exerepair tests tools
python -m compileall -q exerepair tests tools main.py
```

专项测试覆盖 Enigma 算法向量、元数据和 section 恢复、32 位 salt 边界、EVB v1/v3 夹具、路径防护、应用服务输出和 CLI 路由。