# Enigma 载荷修复

## 输入与配置

本流程对应 `tayutama-zero-dl-enigma-1.31` 配置。输入长度为 `4,116,480` 字节，
SHA-256 为 `a94e0f2a34c365f6238e6734e6bf9cb5574560c2bd26faacf1b826c49e7658f1`。
输入名称可以改变，但摘要和长度必须同时匹配。

构建器要求 PE32、固定映像基址、未启用 ASLR，并有安全的空白节表槽。
首次运行时捕获要求 Windows 和 64 位 Python；清单重放不需要 Frida。
输出 EXE 仍使用目标程序的外部资源，改变输出目录时应准备相应资源。

## 引导、容器与引擎

`PEImage.parse()` 验证头部和文件范围；`decode_enigma_bootstrap()` 根据指令结构
识别逐层 XOR 解码参数；`extract_enigma_engine()` 返回分析对象、容器文件偏移和引擎字节。
容器按 DWORD 还原后使用有界 aPLib 解压，构建时按同一规则重压缩。

`bcj_transform()` 是该引擎观察到的变换，不是通用 x86 BCJ 实现。
`E8/E9` 操作数使用流位置修正；`FF 25` 使用独立累计值；
扫描会跳过已处理操作数。构建前后检查 encode/decode 往返一致。

## 首次恢复

实际载荷描述符使用 source RVA、处理 flags、长度、16 字节前缀与预期 CRC。
恢复上下文的硬件分量模式、密钥长度、描述符集合和原密文前缀都需要与配置一致。

1. 在工作目录中的临时副本启动捕获，仅复制初始化所需相邻 DLL。
2. 捕获适配器在已配置的运行点读取描述符，并停驻自己创建的进程。
3. CPU 或 OpenCL 在给定 32 位范围内执行 MD5/RC4/aPLib 前缀结构筛选。
4. 结构候选再次解密完整载荷，比较长度、CRC32 和配置中的 SHA-256。
5. 全部七个载荷均校验一致后返回；上下文在应用层清理。
6. 保存载荷与相对路径清单，下次运行先重新校验缓存。

`auto` 尝试 OpenCL，不可用时选择 CPU；显式 `opencl` 不自动降级。
业务恢复批次为最多 `2^20` 个候选，搜索游标只记录已完成的边界与输入摘要。
匹配分量和派生密钥只在恢复内存中使用，不写入日志、清单或生成 EXE。
这不是对 Python 临时内存物理擦除的保证。

## 生成副本

原文件中的密文保留，新增 `.repair` 节保存位置无关复制 helper、查找表和已校验载荷。
helper 以描述符的 source RVA 匹配，向原引擎分配的缓冲区复制规定长度的字节；
保存并恢复通用寄存器和 EFLAGS。原 CRC、解压和初始化路径继续运行。

| 修改点 | 行为 |
| --- | --- |
| `VM[0x26DE]` | 已校验分支的 `JZ` 改为 `JMP` |
| `VM[0x4AD3]` 表项 | 指向现有 `MOV AL,1` 指令 |
| 原谓词记录 | 验证仅有一个表引用后退休 |
| `VM[0x489F]` | 原 KSA 调用改为载荷复制 helper |
| `VM[0x48A6]` | 原 PRGA 调用改为 `RET 8` |

每处都比较预期记录与原字节，索引和表范围经过校验。
`RET 8` 与原调用的两个栈参数对应，不能用普通 `RET` 替代。
原 CRC 分支不修改。修改引擎重压缩后必须放入原容量，否则构建失败。

## 命令与清单

在项目根目录运行，示例文件名和目录按实际输入替换：

```powershell
python -m pip install -e ".[recovery]"
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --work-dir .\cache
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --recovery-manifest .\cache\recovered-payloads.json
```

v2 清单为 `exerepair.recovered-payloads.v2`；兼容读取的旧清单格式为
`seep.recovered-payloads.v1`。清单记录源 RVA、文件偏移、长度、flags、CRC、SHA-256
与相对载荷文件名。`load_payload_manifest()` 重新读取字节并核对全部值。
旧清单的 `destination_rva` 不用于写入地址。

## 结果与错误

结果文件为输出 EXE 和同名前缀的 `.DIFF.json`、`.VERIFICATION.json`、
`.ROLLBACK.sh`、`.baseline.exe`。输入身份变化、捕获超时、范围无匹配、
载荷校验失败、VM 原字节不一致、节表空间不足或压缩超容量都会停止相应流程。

自动构建报告只确认文件级结果，`runtime_launch_verified` 保持 `false`。
实际运行及回滚行为应在独立副本和同一输入条件下另行记录。
代码接口分别见 [适配器](../exerepair/adapters/README.md)、
[构建流程](../exerepair/workflows/README.md) 与 [应用发布](../exerepair/application/README.md)。
