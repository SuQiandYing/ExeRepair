# 原生依赖与第三方发行包

本目录保留完整、未修改的 aPLib 1.1.1 上游发行包及许可说明。

| 文件 | 用途 |
| --- | --- |
| [aPLib-1.1.1.zip](aPLib-1.1.1.zip) | 完整上游文件、DLL、资料和许可；不展开到源码目录 |
| [NOTICE.md](NOTICE.md) | 第三方归属与发行包摘要 |

## 加载步骤

1. `adapters.aplib.resolve_library()` 检查包 SHA-256。
2. 根据当前 Python 指针宽度选择 `dll` 或 `dll64` 对应的 `aplib.dll`。
3. 要求匹配包成员唯一，读取 DLL 并写入临时缓存；内容相同时复用缓存。
4. `AplibCompressor` 绑定 Windows ABI 并检查工作区、目标容量及返回值。

发行包 SHA-256：
`c35c6d3d96cca8a29fa863efb22fa2e9e03f5bc2c0293c3256d7af2e112583b3`。
显式 DLL 参数优先于环境变量和内置包，外部库的架构及可加载性由调用时检查。
项目自身新增文档不会修改上游压缩包；该目录没有独立 Python 功能入口。

## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_runtime_repair.py -k complete_unmodified_native_distribution -q
```

[返回项目总说明](../../../README.md)
