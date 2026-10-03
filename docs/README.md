# 文档与适配说明

本目录组织用户说明、架构说明和已配置构建的技术边界，不包含执行入口。
总入口在项目根 README；路径示例统一采用相对目录和通用文件名。

| 文档 | 阅读内容 |
| --- | --- |
| [DESIGN.md](DESIGN.md) | 分层、加载、构建、发布、并发与验收层级 |
| [ENIGMA_RUNTIME_REPAIR.md](ENIGMA_RUNTIME_REPAIR.md) | 载荷身份、首次恢复、缓存与运行时复制节 |
| [EXHIBIT_DMM_REPAIR.md](EXHIBIT_DMM_REPAIR.md) | 原生保护调用、跳板、重定位与容器迁移 |
| [SINGLE_SAMPLE_RESEARCH.md](SINGLE_SAMPLE_RESEARCH.md) | 字段含义、策略区别和验收限制 |

## 维护约定

文档只描述当前代码提供的入口；配置摘要、版本和参数更新应与源代码一致。
函数接口和各字段以对应目录 README 为索引。命令在项目根运行，示例文件名
由读者替换，未记录任何个人电脑目录。生成的 JSON 结果可能含调用者真实
输入位置，但这类运行记录不直接复制到项目 Markdown。

验证文档更新时检查相对链接、目录覆盖、参数名称与压缩快照一致性。
`docs.zip` 是项目快照，不把自身或临时缓存递归打包。

[返回项目总说明](../README.md)
