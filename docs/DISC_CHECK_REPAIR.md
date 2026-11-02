# 光盘检查与安装目录兼容

## 输入与调用

本流程处理具有已验证配置的 PE32 输入，也可发现有限范围内的通用 PE32
加载结构。内置及外部配置都需要完整 SHA-256 和长度匹配；通用候选先绑定
当前输入摘要，再从临时进程采集受限的运行时证据。构建器继续核对入口字节、
映像地址、节表、签名及重定位约束。文件名不参与检查点判定，未知版本不套用
邻近版本的偏移。

```powershell
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe
```

CLI、桌面“修复副本”和 `RepairService.repair()` 使用同一流程。
只读检查不启动目标程序；精确配置的构建不需启动目标。
通用候选的修复需要 Windows 和 Frida，运行临时副本定位模块检查及受支持的
主映像消息/重试分支。该流程不使用 GPU、aPLib 或 `--recovery-manifest`。

## 通用候选与临时运行

桌面界面拖入文件后，如果匹配受支持的加载结构，会显示“通用结构待运行时确认”。
资源不在 EXE 所在目录或与其版本不匹配时，可先点击“资源目录…”选择匹配的目录。
该目录同时作为自动输出副本的目录；不选择时使用 EXE 所在目录。
通过 `RepairService.repair(..., disc_resource_dir=...)` 可在 API 中设置同一选项，
如另行显式指定 `output` 则输出位置以 `output` 为准。
点击“修复副本”后，工具将 EXE 和所选资源目录（默认 EXE 目录）中的有限数据文件
复制到临时目录运行：
只复制受支持的数据扩展名，单文件不超过 8 MiB、总量不超过 64 MiB、最多
128 个文件，不递归目录。探测可能自动取消该临时进程中带“取消”按钮的标准对话框。
不会复制或覆盖原始 EXE 及其资源；临时目录会在进程退出后清理。

**临时目录不是安全沙箱。** 临时程序仍可能访问用户数据、网络或系统设置，
也可能读取其通过绝对路径访问的文件；只对可信且有权处理的程序使用。
临时进程异常退出会报告退出码并停止发布；未观察到主映像消息时仅标注运行
未验证，不应当作完整修复成功。工具不会自动搜寻、替换或改写版本不匹配的资源。

模块证据须满足唯一调用关系、返回尾声和成功字段；主映像补丁仅在实际观察到
光盘提示且同一检查的条件跳转、消息调用和重试路径唯一匹配时生成。
支持当前实现中有界的短/长跳转和间接调用形式，不代表能处理所有 EXE 或所有弹窗。
输出副本默认位于源目录或所选资源目录，仍需要对应版本的资源和正确工作目录；必要时应使用
软件原本的启动方式。生成报告的 `runtime_launch_verified` 仍为 `false`。

## 外部配置

已独立分析并验证检查点的输入，可以显式提供 JSON 配置，而无需修改工具源码：

```powershell
python -m exerepair --inspect TARGET.exe --disc-profile .\local-profile.json
python -m exerepair TARGET.exe --disc-profile .\local-profile.json -o .\output\OUTPUT.exe
python -m exerepair --gui --disc-profile .\local-profile.json
```

下面只是字段模板，尖括号内容必须替换为**当前输入**的实际验证结果；
它不是能直接套用的配置，也不会自动定位检查点：

```json
{
  "format": "exerepair.disc-profile.v1",
  "name": "local-profile",
  "baseline_sha256": "<64 hexadecimal characters>",
  "baseline_size": "<input size in bytes>",
  "image_base": "<image base>",
  "entry_rva": "<entry RVA>",
  "entry_bytes": "<entry guard bytes in hexadecimal>",
  "module_image_size": "<late-loaded module image size>",
  "caller_return_rva": "<caller return RVA>",
  "caller_guard": "<caller guard bytes in hexadecimal>",
  "return_rva": "<return epilogue RVA>",
  "return_guard": "<return epilogue guard bytes in hexadecimal>",
  "success_flag_rva": "<success flag RVA>",
  "allow_dynamic_base_without_relocations": false,
  "runtime_note": "Check the required external resources separately."
}
```

数值字段填写 JSON 非负整数，或 `"0x"` 开头的十六进制字符串，范围为
32 位无符号整数。字节字段填写连续、偶数位的十六进制字符串。
`allow_dynamic_base_without_relocations` 与 `runtime_note` 可省略，
分别默认为 `false` 和空字符串；动态基址选项仅在已验证该输入满足构建器的
固定基址要求时显式启用。加载器拒绝未知字段、重复字段和超过 64 KiB 的配置，
并验证配置自身的范围和保护字节形式。

外部格式只描述现有的延迟模块标量返回检查，不支持导入任意静态补丁、
安装目录替换、注册表分派或地区补丁。配置按本次调用使用，不注册到全局配置表；
摘要或长度不匹配会在生成输出前失败。检查只验证身份、配置形式和 PE 解析；
构建时仍执行入口、映像、节表和重定位验证，运行时回调仍检查模块、调用方及尾声。
这些保护不证明用户提供的 RVA 语义正确，运行结果和资源完整性仍须单独验证。

修复服务只写 EXE 和事务文件，不复制外部资源、不修改现有配置文件，
也不会推断不同程序或版本所需资源。`runtime_note` 仅用于向 CLI、界面和报告
传递用户填写的提示，不参与补丁构建或资源校验。

## 配置与实现边界

| 组件 | 职责 |
| --- | --- |
| `domain.recovery.DiscCheckProfile` | 输入身份、PE 约束、调用方及模块保护条件 |
| `domain.recovery.PortableSetupProfile` | 可选的安装目录调用点、字符串 ABI 参数和原字节 |
| `workflows.profiles` | 保存精确输入对应的参数，不保存运行日志 |
| `application.disc_profiles` | 加载显式提供的外部配置并验证字段形式，不全局注册 |
| `workflows.disc_discovery` | 只读发现候选并验证模块、主映像的有限结构证据 |
| `adapters.disc_discovery` | 复制受限资源、运行临时进程并采集证据 |
| `workflows.portable_setup` | 校验参数，纯函数生成调用替换、保护条件和字符串 stub |
| `workflows.disc_repair` | 合并运行时计划，生成代码/状态节及可重放补丁 |
| `application.recovery.RepairService` | 检查发布冲突，写入并重读事务产物 |

构建逻辑只读取配置字段，不根据配置名称、EXE 文件名或产品名称选择分支。
`portable_setup` 默认为 `None`；不能仅打开一个布尔开关就适配任意输入。
不同配置的字节保护、映像对象和调用约定不能混用。

对于在主 PE 映像初始化阶段执行的检查，配置可以提供
`static_patch_sites`。构建器会逐点核对原字节，在原节内生成等长替换，
不添加运行时节、不改变入口、不依赖固定加载地址；每个替换点仍受完整
摘要、入口保护字节、可执行节和补丁重放校验约束。

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

静态补丁配置不使用上述回调和状态节；其报告策略为
`static-disc-check`，输出长度与节表保持不变，适用于无需等待模块解密的
主映像检查。

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
所有注册表访问；不修改系统区域设置，不处理存档，也不补齐缺失资源。

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
目标机器的绝对路径、注册表键、截图和逐轮实验日志保存在独立验证目录，
不写入产品文档。

## 开发回归

```powershell
python -m pip install -e ".[dev,verification]"
python -m pytest tests/test_disc_discovery.py tests/test_disc_repair.py tests/test_disc_profiles.py tests/test_portable_setup.py -q
```

测试使用合成 PE、虚拟地址和 API 替身，不读取真实安装目录。
覆盖精确配置、无配置名称分支、补丁重放、RX/RW 分离、范围和冲突校验、
每字节保护、超时不写入、寄存器/栈保持、Unicode 目录及 UTF-16 长度边界。
外部配置测试还覆盖格式、重复字段、错误输入身份、CLI 和桌面控制器。
机器码测试使用可选 Unicorn，在隔离子进程中执行；未安装时明确跳过。

[返回工作流索引](REPAIR_WORKFLOWS.md)
