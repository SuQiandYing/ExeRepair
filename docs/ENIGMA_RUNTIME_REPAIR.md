# 引擎解析与载荷恢复

## 输入与准备

本流程接收 EXE、修复参数、缓存目录和压缩器。文件长度、完整 SHA-256、
PE 结构与原始字节分别用于输入检查，不以文件名判断处理方式。
输入校验由 `RepairService.inspect()` 与流程构建器执行。

构建器检查 PE32、映像基址、ASLR 状态及节表空间。
首次捕获需要 Windows、64 位 Python 与恢复依赖；已有清单先重新校验，
通过后直接进入构建，不再次加载捕获依赖。输出副本仍使用输入程序的外部资源。

## 引导与引擎解析

1. `PEImage.parse()` 读取头部、节表和文件范围。
2. `decode_enigma_bootstrap()` 按指令结构识别解码参数。
3. `extract_enigma_engine()` 返回容器分析、文件偏移和引擎字节。
4. 容器按参数执行 DWORD 变换和有界 aPLib 解压。
5. 构建时执行对应重编码、重压缩与往返比较。

`bcj_transform()` 按引擎格式处理 `E8/E9` 和 `FF 25` 操作数。
扫描跳过已处理的操作数，编码与解码返回独立字节。
该变换用于这里的容器编码，不作为其他格式的 BCJ 实现。

## 捕获与恢复

载荷描述符包含源 RVA、处理标记、长度、前缀及预期 CRC。
恢复参数包含分量域、密钥长度、描述符集合与输入校验信息。

1. 在隔离工作目录中准备临时副本和初始化依赖。
2. 捕获适配器在参数指定的运行点读取描述符，并管理自己创建的进程。
3. CPU 或 OpenCL 在给定范围执行 MD5、RC4 与 aPLib 前缀结构筛选。
4. 对候选执行完整恢复，比较长度、CRC32 和 SHA-256。
5. 参数要求的全部载荷校验通过后返回，并清理捕获上下文。
6. 保存相对路径清单；后续读取重算载荷摘要。

`auto` 尝试 OpenCL，不可用时选择 CPU；显式 `opencl` 不自动降级。
搜索批次和游标记录已经完成的范围及输入摘要。
派生值只在恢复内存中使用，不写入日志、清单或输出副本。

## 副本构建

原始密文保留，新增 `.repair` 节存放复制 helper、查找表和已校验载荷。
helper 按描述符源 RVA 查找数据，将规定长度的字节复制到引擎缓冲区，
保存并恢复通用寄存器与 EFLAGS，继续原有完整性检查和初始化路径。

控制流编辑的位置、预期记录和源字节由修复参数提供。
`patch_gate()` 校验 VM 表、记录范围与引用；构建器记录每项修改，
并保持调用的参数、返回和栈清理约定。引擎重封装还要验证压缩容量与往返。

## 命令和清单

在项目根目录运行：

```powershell
python -m pip install -e ".[recovery]"
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --work-dir .\cache
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --recovery-manifest .\cache\recovered-payloads.json
```

清单记录源 RVA、文件偏移、长度、flags、CRC、SHA-256 与相对载荷文件名。
`load_payload_manifest()` 重新读取载荷并验证记录，不仅依据清单中的标志。
清单格式标记用于解析兼容，不是产品版本号；兼容字段不作为新增写入地址。

## 输出与错误

输出包含 EXE 副本、差异 JSON、验证 JSON、回滚脚本与原始基线。
输入检查失败、捕获超时、搜索无匹配、载荷摘要不符、原字节变化、
节表空间不足或压缩容量不足时，流程返回相应错误。

文件级验证与实际运行分别记录；`runtime_launch_verified` 默认是 `false`。
接口见 [适配器](../exerepair/adapters/README.md)、
[构建流程](../exerepair/workflows/README.md) 和
[应用发布](../exerepair/application/README.md)。
