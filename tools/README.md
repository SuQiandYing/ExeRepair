# 开发验证与性能工具

本目录为独立开发脚本，不作为主程序运行时入口。

## 补丁重放检查

`verify_repair_dev.main(argv)` 接收 `baseline`、`modified` 与可选 `--diff`。
未指定差异时读取生成副本旁的同名 `.DIFF.json`，调用 `apply_binary_patch()`，
要求重放输出与修改文件逐字节一致。成功打印输入/输出 SHA-256、
`patch_replay_verified: true` 和 `runtime_launch_verified: false`；失败打印 stderr 并返回 `2`。
脚本只读文件，不启动游戏，不修改输入。

```powershell
python tools\verify_repair_dev.py --help
python tools\verify_repair_dev.py .\samples\BASELINE.exe .\output\OUTPUT.exe --diff .\output\OUTPUT.exe.DIFF.json
```

## 合成 OpenCL 基准

`benchmark_recovery_dev.main()` 接收：

| 参数 | 默认值 | 行为 |
| --- | --- | --- |
| `--package-root` | 必填 | 待测源码根目录，加入 Python 搜索路径 |
| `--count` | `2^23` | 每轮扫描数；当前内置合成向量要求已知候选落入区间 |
| `--rounds` | `3` | 正式计时轮数，需为正值 |
| `--output` | 必填 | JSON 报告路径 |

脚本构造合成数据，用 aPLib 压缩，再进行 CPU/GPU 位图对照、高位范围检查、
缓冲区重复调用、预热与正式扫描。各轮位图摘要必须一致；
记录设备、工作组、初始化时间、每轮时间、中位数与吞吐。
需要 Windows、匹配位数的 aPLib、NumPy/Numba 和可用 OpenCL GPU，不自动降级。
该脚本当前以断言验证合成工作负载，不是任意范围的通用参数校验器。

```powershell
python tools\benchmark_recovery_dev.py --help
python tools\benchmark_recovery_dev.py --package-root . --count 8388608 --rounds 3 --output .\reports\benchmark.json
```

基准反映当前设备与合成任务，不等于完整首次恢复耗时。
两个脚本都不读注册码、自动扫描其他游戏或验证真实启动。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `benchmark_recovery_dev.py`

合成 OpenCL 基准与独立 CPU 对照，写出 JSON。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `main()` | 解析本模块参数并执行所述入口；返回退出状态，具体输入见本节说明。 |


### `verify_repair_dev.py`

只读补丁重放检查，输出文件摘要与验证层级。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `main(argv=None)` | 解析本模块参数并执行所述入口；返回退出状态，具体输入见本节说明。 明确抛出：`RecoveryError`。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python tools/verify_repair_dev.py --help
python tools/benchmark_recovery_dev.py --help
```

[返回项目总说明](../README.md)
