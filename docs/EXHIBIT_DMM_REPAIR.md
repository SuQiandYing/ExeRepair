# ExHIBIT 原生调用修复

## 适用身份

本说明对应 `exhibit-hoshizora-tp01-dmm-enigma-1.31`。
输入长度为 `3,186,688` 字节，
SHA-256 为 `a903a9d97b62d3d52fb62a1f648f836384b41dd089afd967808ab8f7808a2a82`。
该配置匹配的是精确构建，不表示所有 DMM 或 Enigma 文件采用相同处理方式。

```powershell
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe
```

在准备目标程序所需 DLL、INI、资源和剧本的目录中使用输出副本。
该策略不使用恢复清单、运行时捕获、CPU/GPU 搜索；
指定 `--recovery-manifest` 会返回错误。引擎重封装仍使用 aPLib 压缩器。

## 原生跳板行为

配置的调用 RVA 为 `0x183BB`，保护位置 RVA 为 `0x183B6`，
十字节保护模式为 `68 04 4A 4C 00 FF D0 83 C4 04`。
这些是运行时 RVA，不是直接在原始磁盘文件中按同数值修改的偏移。

跳板保存寄存器与 EFLAGS，比较完整保护模式；一致时将 `FF D0` 的两字节
调用改为 `90 90`，然后恢复现场、重放迁移的调度 MOV 并返回原控制流。
不匹配时不向调用位置写入。参数栈清理与模块卸载沿用原程序路径。

原引擎调度位置改为相对跳转。被迁移 MOV 对应的 HIGHLOW 重定位记录经过
所在块、位置与目标 RVA 校验后退休；不能仅扫描相同的 16 位数值来替换。
构建要求固定基址 PE32、未启用 ASLR，以及保护调用所在节可写。

## 引擎容器迁移

修改引擎做 BCJ 重编码、aPLib 压缩和重解压比较。
该策略追加两个节，避免依赖原容器剩余容量：

| 节 | 内容 | 属性 |
| --- | --- | --- |
| `.repair` | 原生跳板 | 可读、可执行 |
| `.epack` | 新压缩引擎容器 | 可读、可写、不可执行 |

引导层中的两组容量与 source RVA 参数先与配置值比较，再更新到新容器，
随后反向还原引导层编码。原引擎容器和其他游戏载荷字节继续保留。
需要两个连续空白节表槽，按文件/内存对齐更新节数与 PE 大小字段。

## 构建与发布检查

`build_native_repair()` 检查输入和引擎摘要、保护范围、原调度 MOV、
重定位块、引导参数、节表空间、BCJ 往返、压缩往返和输出引擎重提取。
最后重放差异，要求得到完全相同的候选字节。

`RepairService` 共用修复发布逻辑：拒绝输入别名与硬链接覆盖，
检查现有产物，原子写入并重读输出、副本基线、差异、验证和回滚脚本。
该流程不启动探测或游戏进程。

| 代码 | 职责 |
| --- | --- |
| `domain/recovery.py` | `NativeCallProfile` 配置契约 |
| `workflows/profiles.py` | 身份匹配 |
| `workflows/native_repair.py` | 跳板、重定位、容器迁移与重放 |
| `application/recovery.py` | 分流、覆盖检查、发布和回滚 |
| `cli.py`、`ui/viewmodel.py` | 静态修复方法与结果呈现 |
| `tests/test_native_repair.py` | 保护字节、寄存器、标志、栈、构建约束与入口 |

表中的代码名称相对于 `exerepair` 包目录；测试名称相对于项目根目录。
目录级接口见 [流程说明](../exerepair/workflows/README.md) 与
[测试说明](../tests/README.md)。

## 验收边界

`runtime_launch_verified` 默认是 `false`。文件级构建成功不代替实际窗口、
资源和剧本加载、交互与运行回滚验证。实验运行记录应使用独立的
`VERIFICATION.txt` 或 JSON 账本，不将个人电脑路径写入项目说明。
未知构建、保护字节变化或启用不同加载方式时，需要独立适配。
