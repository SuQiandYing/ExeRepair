# ExeRepair

ExeRepair 是用于本地 EXE 容器检查、内容提取和特定构建修复的工具。
提供命令行、桌面界面与 Python API。要求 Python **3.10 或更高版本**。

## 功能与适用范围

| 功能 | 输入 | 处理方式 | 输出 |
| --- | --- | --- | --- |
| 只读检查 | EXE 文件 | 解析容器或匹配修复配置，不启动目标程序 | 版本、模式、区块数量或构建信息 |
| 容器提取 | V1–V7 容器、相邻的必要文件 | 解析配置、恢复主程序与指定资源区块 | 主程序副本、按相对位置复制的资源、失败区块信息 |
| 载荷修复 | 与 `RepairProfile` 身份一致的构建 | 复用校验清单；无清单时隔离捕获并恢复载荷 | 含 `.repair` 节的 EXE 及差异、验证、回滚文件 |
| 原生调用修复 | 与 `NativeCallProfile` 身份一致的构建 | 静态生成带字节保护检查的跳板并重新封装引擎 | 含 `.repair` 和 `.epack` 节的 EXE 及事务文件 |
| 桌面操作 | 拖入或选择一个 EXE | 自动选择提取或已配置修复流程，显示状态与日志 | 与相应应用服务一致的结果 |
| 补丁复核 | 原始副本、生成副本、差异 JSON | 重放补丁并逐字节比较 | 文件摘要与重放结果 |

当前修复配置只有 `tayutama-zero-dl-enigma-1.31` 与
`exhibit-hoshizora-tp01-dmm-enigma-1.31`。配置匹配同时比较文件长度和完整 SHA-256；
文件名或相似的引擎版本不构成匹配条件。项目不提供依赖参考 EXE 的配对修复入口。
结构校验、补丁重放通过与实际运行通过是不同的验证层级。

## 安装与依赖

在项目根目录运行：

```powershell
python -m pip install -e .

# 首次载荷捕获和恢复所需的可选依赖
python -m pip install -e ".[recovery]"

# 开发测试与静态检查
python -m pip install -e ".[dev]"
```

| 依赖 / 环境 | 用途 | 何时需要 |
| --- | --- | --- |
| Windows | 桌面交互、原生 DLL、运行时捕获 | 完整产品流程 |
| Tkinter | 桌面控件 | 使用 GUI；由 Python 环境提供 |
| `tkinterdnd2` | 文件拖放 | 基础安装依赖；不可导入时视图退回普通 Tk |
| Frida、psutil | 隔离子进程的捕获与清理 | 首次载荷恢复；需要 64 位 Python |
| NumPy、Numba | CPU 筛选与校验 | 首次载荷恢复 |
| OpenCL 驱动 | GPU 结构筛选 | 选择 GPU 后端；驱动不由 pip 安装 |
| 内置 aPLib DLL | 引擎重压缩 | 两种修复构建；按 Python 位数选择 DLL |
| pytest、Ruff | 回归与静态检查 | 开发验证 |

只读检查、容器提取和已恢复清单重放不加载运行时捕获依赖。
原生调用修复不使用载荷清单、Frida 或搜索后端。
第三方 aPLib 发行包保留完整内容，许可见 [原生依赖说明](exerepair/adapters/native/README.md)。

## 快速使用

以下命令中的文件名及相对目录是示例输入，应替换为实际文件。
`TARGET.exe` 为输入，`OUTPUT.exe` 为新输出；不要将两者设置为同一个文件。

```powershell
# 只读检查
python -m exerepair --inspect TARGET.exe

# 自动识别并处理；默认生成 TARGET_crack.exe
python -m exerepair TARGET.exe

# 指定独立输出和恢复缓存
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --work-dir .\cache

# 载荷配置：复用已有清单，不再捕获或搜索
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --recovery-manifest .\cache\recovered-payloads.json

# 有界搜索；仅用于需要载荷恢复的配置
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe --backend cpu --search-start 0x0 --search-count 0x100000

# 桌面入口
exerepair-ui
python main.py

# 查看完整参数
python -m exerepair --help
```

不提供位置参数或指定 `--gui` 时，命令行启动桌面界面。
已安装的 `exerepair` 命令与 `python -m exerepair` 使用相同参数。

### 参数说明

| 参数 | 默认值 | 含义 / 生效范围 |
| --- | --- | --- |
| `executable` | 不提供时打开 GUI | 输入 EXE；只有一个目标 |
| `-i` / `--inspect` | 关闭 | 检查后返回，不执行提取或修复 |
| `-o` / `--output` | 输入名加 `_crack` | 容器或修复输出 EXE 路径 |
| `--gui` | 关闭 | 进入 GUI；可携带初始输入文件 |
| `--force` | 关闭 | 仅修复事务使用，允许替换不同的已存在产物 |
| `--recovery-manifest` | 自动检查当前工作目录中的缓存 | 载荷修复清单；原生调用配置拒绝此选项 |
| `--work-dir` | 输出目录下 `.exerepair/<输入摘要前12位>` | 缓存、搜索游标和隔离捕获目录 |
| `--aplib-dll` | 内置匹配架构 DLL | 显式指定压缩器库；环境变量 `EXEREPAIR_APLIB_DLL` 也可提供 |
| `--backend` | `auto` | `auto` 优先 OpenCL，不可用时 CPU；`opencl` 不自动降级 |
| `--search-start` | `0` | 搜索起点；接受十进制或 `0x` 数值 |
| `--search-count` | `2^32` | 搜索候选数；与起点共同满足 32 位范围限制 |

CLI 成功或只读检查成功返回 `0`；应用层识别、读取、提取或修复失败通常返回 `2`。
参数解析失败也返回 `2`。GUI 返回值由其主事件循环结束后的入口返回值决定。

## 桌面流程

1. 拖入 EXE 或点击“选择文件”；加载任务在工作线程中执行。
2. 容器匹配后显示版本、Overlay、主程序、区块及模式，按钮为“提取”。
3. 精确修复配置匹配后显示配置身份与处理方法，按钮为“修复副本”。
4. 点击按钮执行已识别流程；处理时按钮禁用，队列将结果交回 Tk 主线程。
5. 查看输出位置、失败信息和日志。未知构建只显示未匹配，不复用其他配置的偏移。

## 输出、缓存与回滚

### 容器提取

生成主程序并复制指定资源区块。失败记录保存在 `ExtractionResult.failures`。
该流程不会自动生成下面的修复事务辅助文件，也没有修复事务的 `--force` 检查。
集成调用应选择独立输出位置；底层文件写入可能替换现有输出。
通过 API 的 `output_directory` 可以让主程序与资源统一写入独立目录。

### 修复事务

```text
OUTPUT.exe
OUTPUT.exe.DIFF.json
OUTPUT.exe.VERIFICATION.json
OUTPUT.exe.ROLLBACK.sh
OUTPUT.exe.baseline.exe
```

| 文件 | 作用 |
| --- | --- |
| 输出 EXE | 修复后的独立副本 |
| `DIFF.json` | 输入/输出摘要、长度及 replace/append 二进制编辑记录 |
| `VERIFICATION.json` | 文件级校验结果、使用配置、修改点及原文件状态 |
| `ROLLBACK.sh` | 接受一个目标副本，从同目录基线恢复并验证摘要 |
| `baseline.exe` | 输入文件的原始字节 |

修复服务拒绝输出指向输入及其硬链接，默认拒绝覆盖内容不同的现有产物。
发布时逐个原子写入并重读，前后检查输入 SHA-256；多文件发布不是一个文件系统级整体事务。
载荷缓存使用相对文件名，重新读取时重算 CRC32 与 SHA-256，不仅依赖清单标志。
生成报告中的 `runtime_launch_verified` 默认是 `false`，工具不会自动证明外部资源完整或游戏可运行。
回滚脚本需要 POSIX shell、`cp`、`cmp` 以及 `sha256sum` 或 `shasum`；
目标副本参数需要按脚本要求提供绝对路径，本文不记录具体电脑目录。

## Python API

```python
from pathlib import Path
from exerepair.api import ContainerService, ExtractionOptions, RepairService

containers = ContainerService()
inspection = containers.inspect("TARGET.exe")  # 只读容器检查
result = containers.extract(
    "TARGET.exe",
    ExtractionOptions(output_directory=Path("output")),
)
print(result.success, result.failed_indices)

repairs = RepairService()
profile = repairs.inspect("TARGET.exe")  # 仅匹配已配置修复构建
# 针对载荷配置，可传入已校验的缓存清单
repaired = repairs.repair(
    profile.source_path,
    Path("output") / "OUTPUT.exe",
    manifest=Path("cache") / "recovered-payloads.json",
)
print(repaired.output_sha256)
```

上面的容器与修复示例是两条独立用例，不表示同一个输入一定同时支持两条流程。
原生调用配置调用 `repair()` 时不要传入 `manifest`。
接口细节见 [包入口说明](exerepair/README.md) 与 [应用层说明](exerepair/application/README.md)。

## 目录与功能文档

| 目录 | 详细说明 |
| --- | --- |
| `docs` | [使用说明、设计与构建适配索引](docs/README.md) |
| `exerepair` | [入口、公共 API 和兼容导出](exerepair/README.md) |
| `exerepair/application` | [加载、提取、修复发布和结果对象](exerepair/application/README.md) |
| `exerepair/domain` | [枚举、数据字段、路径策略和错误契约](exerepair/domain/README.md) |
| `exerepair/formats` | [PE、容器、引导层、aPLib 和 BCJ](exerepair/formats/README.md) |
| `exerepair/security` | [CRC32、伪随机序列和 XOR](exerepair/security/README.md) |
| `exerepair/adapters` | [文件系统、DLL、捕获、CPU / GPU 后端](exerepair/adapters/README.md) |
| `exerepair/adapters/native` | [第三方发行包、架构选择与许可](exerepair/adapters/native/README.md) |
| `exerepair/workflows` | [配置匹配、构建器和二进制补丁重放](exerepair/workflows/README.md) |
| `exerepair/ui` | [窗口、线程、状态机与控制器](exerepair/ui/README.md) |
| `tests` | [测试分组、合成夹具与验证范围](tests/README.md) |
| `tools` | [离线重放验证与合成 GPU 基准](tools/README.md) |

各目录文档列出本目录模块、类字段、函数签名、作用及对应测试。
`docs.zip` 同步保存项目快照，包含当前说明，不递归包含自身或运行时缓存。

## 开发验证

```powershell
python -m pytest -q
python -m ruff check exerepair tests tools
python -m compileall -q exerepair tests tools main.py
python -m exerepair --help
python tools\verify_repair_dev.py --help
python tools\benchmark_recovery_dev.py --help
```

测试包括格式边界、载荷摘要、补丁重放、原文件保护、界面控制器及后端资源生命周期。
部分机器码验证用例需要额外的 Unicorn 开发环境；具体依赖以对应测试导入为准。
合成回归不替代实际目标程序启动、资源加载与运行回滚验收。

## 许可

项目许可见 [LICENSE](LICENSE)；第三方 aPLib 的许可保留在完整发行包内，
并通过 [NOTICE](exerepair/adapters/native/NOTICE.md) 单独说明。
