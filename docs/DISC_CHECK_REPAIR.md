# 光盘检查兼容修复

## 输入与入口

此流程处理已验证配置的 PE32 输入。`identify_profile()` 通过完整 SHA-256
和长度选择 `DiscCheckProfile`，构建器继续核对入口字节、映像基址、节表、
签名与对齐。文件改名不会影响识别；未验证的版本不会套用相近偏移。

```powershell
python -m exerepair --inspect TARGET.exe
python -m exerepair TARGET.exe -o .\output\OUTPUT.exe
```

CLI、桌面“修复副本”与 `RepairService.repair()` 使用同一流程。
检查和构建都不启动输入程序，不加载 Frida、GPU 后端或 aPLib 压缩器；
此流程不接受 `--recovery-manifest`。

## 处理与保护

构建器保留全部原始打包节，仅修改 PE 头并追加两个节：

| 节 | 内容 | 权限 |
| --- | --- | --- |
| `.repair` | 启动入口和有字节保护的单次回调 | 读、执行 |
| `.rstate` | API 地址、临时页权限和完成状态 | 读、写 |

生成副本启动时先解析当前进程的系统 API，不硬编码系统 DLL 基址。
支持的 `GetDriveTypeA` 入口须使用 `FF 25` 间接分派形式；API 缺失、
入口形式不符或入口安装失败时，直接回到原程序入口。

回调在延迟加载的检查模块中核对分配基址、PE 类型、映像大小、
调用方保护字节、完整返回尾声及成功字段的初值。
只有全部匹配时才修改标量返回和成功标志，保留 SEH 恢复及栈清理路径。
随后刷新指令缓存、恢复页权限和 API 分派。通用寄存器和 EFLAGS 均还原，
不改动光驱 API 自身的返回值，也不修改磁盘上的系统 DLL。

### SiglusEngine V2 的无镜像分支

`disc-check-x86-v2` 的运行时代码在延迟加载后才可安全修改。worker 先等待
RVA `0x5A5F0` 出现 `55 8B EC`，再用 `VirtualQuery` 确认代码页可读写。
本样本的磁盘认证分支位于 RVA `0x50B51`：

```text
0F 85 2D 01 00 00  ->  E9 2E 01 00 00 90
JNE 0x450C84            JMP 0x450C84
```

该改动只把“未检测到镜像/光盘”时的失败分支导向原有成功续接点，
不伪造盘符 API 返回值、不写入镜像文件，也不改写原始打包引擎节。
它只验收“磁盘插入提示被跳过”；后续购买确认、资源缺失或其他引擎提示
属于独立状态，不能合并声称为完整游戏流程验收。

输入开启 ASLR 且存在重定位目录、带有数字签名、缺少节表空间或入口保护
不匹配时，构建返回 `RecoveryError`；没有重定位目录但已在配置中确认仍使用
首选基址的样本会显式记录该约束，不会关闭保护或尝试猜测参数。
流程不联网、不读取激活凭据、不运行后台轮询。

## 输出与验证

复用现有发布层，生成 EXE、`DIFF.json`、`VERIFICATION.json`、
`ROLLBACK.sh` 和原始基线。差异使用 `seep.binary-patch.v2`，
可直接使用 `tools/verify_repair_dev.py` 重放。

文件级报告的 `runtime_launch_verified` 保持 `false`：
构建成功不代表外部游戏资源完整。独立运行若已越过原光盘提示、
进入缺少配置文件的引擎报错，可记录为光盘检查验收通过，
但不能据此声称全部游戏流程已验证。运行记录与用户说明分开保存。

## 接口与回归

| 接口 | 职责 |
| --- | --- |
| `domain.recovery.DiscCheckProfile` | 不可变身份、入口和模块内保护参数 |
| `workflows.disc_repair.disc_helper()` | 纯字节生成 RX 代码、RW 状态和布局信息 |
| `workflows.disc_repair.build_disc_repair()` | PE 约束、构建、重读、原节保护和差异重放 |
| `application.recovery.RepairService` | 分流、别名防护、发布和回滚文件 |

```powershell
python -m pytest tests/test_disc_repair.py -q
```

测试使用合成 PE 和 API 替身，覆盖每个保护字节、入口失败、模块重定位、
寄存器/标志/栈保持、单次执行、不覆盖其他分派更新、CLI/GUI 路由及事务。
机器码验证使用可选 Unicorn，在独立子进程中执行；未安装时明确跳过。
