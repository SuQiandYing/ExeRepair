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

输入开启 ASLR、带有数字签名、缺少节表空间或入口保护不匹配时，
构建返回 `RecoveryError`；不会关闭保护或尝试猜测参数。
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
