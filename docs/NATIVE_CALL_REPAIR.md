# 原生调用修复

## 输入与流程

本流程接收 EXE 和压缩器。已验证身份走快速配置；未命中身份时，
先从 PE、Enigma 引导层、嵌入引擎、调度指令和重定位表建立结构候选，
再在一次自有的临时副本进程中定位外层原生调用。候选必须绑定到
`plugin.dll!executeAPI`，并通过唯一候选、返回地址、完整保护字节和节属性检查。
流程不按目标程序名称组织规则，也不为单个程序写白名单文档。

```powershell
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe
```

输出副本需要目标程序所需的 DLL、配置和资源。
`--inspect` 只做静态识别，不启动目标进程；修复未知结构时，
`exerepair.adapters.native_discovery` 只启动完整运行时目录的临时副本，
不向原始进程写内存、不捕获激活值、不搜索密钥。运行时证据按当前样本
摘要和结构字段缓存，`--recovery-manifest` 不属于此流程的输入。
引擎重封装使用 aPLib 压缩器。

## 调用保护与跳板

1. 使用参数中的 RVA 定位调用与保护范围，区分 RVA 和文件偏移。
2. 跳板保存通用寄存器及 EFLAGS，比较完整保护字节。
3. 匹配时编辑调用位置；不匹配时不写入该位置。
4. 恢复现场，重放迁移指令，返回原控制流。

栈清理和资源释放沿用原程序路径。
原引擎调度位置使用相对跳转连接跳板；迁移指令关联的 HIGHLOW
重定位记录按所在块、位置与目标 RVA 校验后处理。
构建检查固定映像基址、PE32、ASLR 状态和调用所在节的可写属性。

## 容器迁移

引擎编辑完成后执行 BCJ 重编码、aPLib 压缩与重解压比较。
构建器追加两个节，将跳板和重新封装的引擎分开存放：

| 节 | 内容 | 属性 |
| --- | --- | --- |
| `.repair` | 原生跳板 | 可读、可执行 |
| `.epack` | 压缩引擎容器 | 可读、可写、不可执行 |

引导参数先与预期容量及源 RVA 比较，再更新为新容器位置。
随后还原引导层编码，并保留原容器和其他载荷字节。
构建需要连续空白节表槽，按文件与内存对齐更新节数和 PE 大小字段。

## 验证与发布

`build_native_repair()` 检查摘要、保护范围、迁移指令、重定位块、
引导参数、节表空间、编码往返、压缩往返和引擎重提取。
最后重放差异，要求候选字节完全一致。

`RepairService` 检查输入别名、现有输出和原文件摘要，
依次原子写入并重读 EXE、副本基线、差异、验证记录与回滚脚本。
此流程不启动目标程序；文件级结果与运行级结果分别记录。

| 模块 | 职责 |
| --- | --- |
| `domain/recovery.py` | 参数契约 |
| `workflows/profiles.py` | 输入匹配 |
| `workflows/native_discovery.py` | Enigma 结构发现、证据绑定和摘要缓存 |
| `adapters/native_discovery.py` | 临时副本运行时定位与清理 |
| `workflows/native_repair.py` | 跳板、重定位、容器迁移和重放 |
| `application/recovery.py` | 分流、输出发布和回滚 |
| `cli.py`、`ui/viewmodel.py` | 操作入口和结果呈现 |
| `tests/test_native_repair.py` | 保护字节、寄存器、栈与流程回归 |

模块路径相对于 `exerepair`，测试路径相对于项目根目录。
详见 [流程接口](../exerepair/workflows/README.md) 与 [测试说明](../tests/README.md)。
