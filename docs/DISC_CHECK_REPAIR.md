# 光盘检查与安装目录兼容

## 输入与调用

本流程处理已有验证配置的 PE32 输入。`identify_profile()` 通过完整 SHA-256
和长度选择 `DiscCheckProfile`；构建器继续核对入口字节、映像地址、节表、
签名及重定位约束。文件名不参与身份判定，未知版本不套用邻近版本的偏移。

```powershell
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe
```

CLI、桌面“修复副本”和 `RepairService.repair()` 使用同一流程。
检查和构建均不启动目标程序，不依赖 Frida、GPU 后端或 aPLib 压缩器；
本流程不接受 `--recovery-manifest`。

## 配置与实现边界

| 组件 | 职责 |
| --- | --- |
| `domain.recovery.DiscCheckProfile` | 输入身份、PE 约束、调用方及模块保护条件 |
| `domain.recovery.PortableSetupProfile` | 可选的安装目录调用点、字符串 ABI 参数和原字节 |
| `workflows.profiles` | 保存精确输入对应的参数，不保存运行日志 |
| `workflows.portable_setup` | 校验参数，纯函数生成调用替换、保护条件和字符串 stub |
| `workflows.disc_repair` | 合并运行时计划，生成代码/状态节及可重放补丁 |
| `application.recovery.RepairService` | 检查发布冲突，写入并重读事务产物 |

构建逻辑只读取配置字段，不根据配置名称、EXE 文件名或产品名称选择分支。
`portable_setup` 默认为 `None`；不能仅打开一个布尔开关就适配任意输入。
不同配置的字节保护、映像对象和调用约定不能混用。

## 运行机制与保护

构建器保留打包节和原始入口，追加两个分离的节：

| 节 | 内容 | 权限 |
| --- | --- | --- |
| `.repair` | 引导入口、受保护的单次回调和可选目录 stub | 只读可执行 |
| `.rstate` | API 地址、临时页权限和完成状态 | 可读写 |

生成副本运行时解析当前进程的系统 API，不硬编码系统 DLL 地址。
回调核对调用来源、模块身份、返回尾声和成功字段后才修改指定代码，
随后恢复 API 分派、页权限及通用寄存器/标志，并刷新指令缓存。
不写入磁盘上的系统 DLL，也不改动其他进程。

需要延迟加载的配置使用有界 worker：等待模块就绪，并核对所有配置的
调用点与字符串函数保护字节。超时或任一保护不匹配时退出，不进入写入路径。
入口安装、API 形式、签名、节表或重定位条件不符时停止构建或保留原运行路径。
具体约束由相应配置给出，不以关闭系统保护替代验证。

## 不依赖安装注册表的目录来源

`PortableSetupProfile` 描述一种已经确认调用约定的 x86 引擎接口：

- `key_check` 替换已识别的安装键检查调用，不创建注册表项。
- `directory_queries` 将安装目录查询替换为引擎已初始化的 **EXE 所在目录**
  UTF-16 字符串复制，供 `exe_dir`、`dat_dir` 一类字段使用。
- `setup_query` 提供配置指定的安装类型；`installed_value` 默认为 `full`。
- 目录复制和文本赋值均调用引擎自己的字符串函数，避免跨分配器释放内存。

这条路径不依赖当前工作目录，也不把目录转换为本地 ANSI 代码页。
切换启动区域后无需重建安装键，但目录对象在调用前已初始化仍是配置前提。
补丁仅替换已识别的安装信息查询，不承诺消除 Windows、图形组件或其他模块的
所有注册表访问；不修改系统区域设置，不迁移存档，也不补齐缺失资源。

### 字符串 ABI 与参数校验

目录对象按 24 字节引擎字符串布局配置，RVA 必须对齐并位于原始包装映像内。
被替换查询使用 `ECX` 传递目标对象，调用者持有的键名参数保持在栈上。
`assign_string` 清理两个栈参数（`ret 8`）；`assign_text` 使用 `EAX` 传文本、
`ESI` 传目标，并清理长度参数（`ret 4`）。新接口必须重新验证这些约定，
不能只更换地址就宣称兼容。

构建时检查完整 `CALL rel32`、非空保护字节、模块范围、保护区重叠、
32 位地址及相对调用距离。安装类型禁止内嵌 NUL 或无效 UTF-16，
长度按 UTF-16 代码单元计算，并受 helper 容量限制。
运行时同时检查调用点及两个字符串函数的原字节。

### 与旧式注册表分派兼容的区别

部分配置保留 `registry_*` 字段，通过进程内 ANSI 分派 shim 提供安装信息；
该路径使用当前工作目录，不能等同于上述 Unicode EXE 目录方案。
它不写入宿主注册表，但仍有自身的键匹配与编码边界。
构建器拒绝在同一配置中混用这两条路径。

## 输出与验证边界

复用统一发布层，输出 EXE、`DIFF.json`、`VERIFICATION.json`、
`ROLLBACK.sh` 和原始基线。差异使用 `seep.binary-patch.v2`，
可用 `tools/verify_repair_dev.py` 重放。

构建报告的 `runtime_launch_verified` 保持 `false`：
结构有效、补丁可重放或合成机器码测试通过，均不等于外部资源已完整加载。
实际验收至少分别记录普通启动、区域模拟启动、不同工作目录、安装键不可用、
资源加载及独立副本回滚后的行为。不要将“原错误消失”当作完整运行成功。
目标路径、注册表键、截图和逐轮实验日志保存在独立验证目录，不写入产品文档。

## 开发回归

```powershell
python -m pip install -e ".[dev,verification]"
python -m pytest tests/test_disc_repair.py tests/test_portable_setup.py -q
```

测试使用合成 PE、虚拟地址和 API 替身，不读取真实安装目录。
覆盖精确配置、无配置名称分支、补丁重放、RX/RW 分离、范围和冲突校验、
每字节保护、超时不写入、寄存器/栈保持、Unicode 目录及 UTF-16 长度边界。
机器码测试使用可选 Unicorn，在隔离子进程中执行；未安装时明确跳过。

[返回工作流索引](REPAIR_WORKFLOWS.md)
