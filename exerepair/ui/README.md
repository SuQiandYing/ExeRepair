# 桌面界面、控制器与状态机

界面采用 Tk。`viewmodel.py` 不依赖 Tk，可用合成服务独立测试；
`view.py` 创建控件，`app.py` 组合窗口与控制器并进入事件循环。
窗口标题统一为 `ExeRepair`。

## 状态与动作

| 状态 | 产生位置 | 可执行操作 |
| --- | --- | --- |
| `empty` | `WorkbenchState.empty()` / `reset()` | 选择或拖入文件 |
| `loading` | `begin_load()` | 等待识别，禁用动作 |
| `ready` | 容器或配置加载成功、处理成功 | 提取或修复副本 |
| `busy` | `begin_action()` | 等待处理，显示进度 |
| `error` | `_fail()` | 查看原因并重新选择文件 |

`WorkflowKind.UNWRAP` 与 `REPAIR` 对应两条产品动作；
`StatusTone` 只表示呈现色调，不决定文件处理方法。
`Row` 和 `WorkbenchState` 是不可变快照，控制器在可重入锁内替换状态。

## 文件与修复识别

`load()` 优先调用容器服务；预期加载错误后尝试修复配置。
能识别引导结构但无严格配置时显示版本未配置；
文件不符合两类结构时显示无法识别。原生配置显示静态构建，无捕获或搜索。

`act(output)` 使用已加载对象，返回 `(状态, 输出路径或 None)`；
`output` 可由集成调用显式提供。进度回调更新状态与日志，
处理失败关闭可执行动作，成功恢复 `ready`。

## 线程、拖放与生命周期

`MainWindow` 在工作线程执行加载和动作，`SimpleQueue` 将结果传回主线程。
`_poll()` 每约 50 ms 消费队列、更新视图和弹窗；`render()` 按状态更新表格和日志。
只在 Tk 主线程操作控件，忙碌时忽略重复动作。
拖放扩展可用时注册文件拖放，不可用时仍可通过文件选择器操作。
`app.main()` 的 `mainloop()` 结束后返回 `0`。

普通 CLI 导入与控制器测试不需要创建可见窗口；
真实 Tk 布局和拖放交互仍需要独立的桌面验证。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

导出本目录对外类型与函数；不复制实现。`__all__` 列出推荐公开符号。

公开导出：`ConsoleController`、`MainWindow`、`WorkbenchState`、`main`。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `main(initial_path: object=None, *, recovery_options: dict &#124; None=None) -> int` | 解析本模块参数并执行所述入口；返回退出状态，具体输入见本节说明。 |
| `__getattr__(name: str) -> Any` | 仅在访问 MainWindow 时延迟导入视图，其余未知名称抛出 AttributeError。 明确抛出：`AttributeError`。 |


### `app.py`

组合 Tk 根窗口、控制器和视图，进入主事件循环。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `main(initial_path: str &#124; Path &#124; None=None, *, recovery_options: dict &#124; None=None) -> int` | 解析本模块参数并执行所述入口；返回退出状态，具体输入见本节说明。 |


### `view.py`

控件、文件选择/拖放、工作线程、事件队列、主线程渲染。

#### `MainWindow`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `MainWindow.__init__(self, root: tk.Tk, initial_path: str &#124; Path &#124; None=None, controller: ConsoleController &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `MainWindow._build(self) -> None` | 创建文件入口、状态区、表格、日志和动作按钮。 |
| `MainWindow._register_drop(self) -> None` | 扩展可用时注册文件拖放，不可用时保持选择器操作。 |
| `MainWindow._on_drop(self, event: object) -> str` | 非忙碌时取首个拖入文件并加载，返回事件终止标志。 |
| `MainWindow.select_file(self) -> None` | 显示文件选择对话框，有选择时请求加载。 |
| `MainWindow.load_path(self, path: str &#124; Path) -> None` | 忙碌时不重复启动，否则后台加载并把结果放入事件队列。 |
| `MainWindow.run_action(self) -> None` | 检查可执行状态，后台执行已加载动作并入队结果。 |
| `MainWindow._poll(self) -> None` | 主线程消费队列、呈现结果和弹窗，再注册下一轮轮询。 |
| `MainWindow.render(self, state: WorkbenchState) -> None` | 按不可变状态更新标签、色调、按钮、表格和日志，不执行文件用例。 |


### `viewmodel.py`

无 Tk 状态机与线程安全控制器，分发已识别处理动作。

#### `WorkflowKind`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `UNWRAP` | `'unwrap'` |
| `REPAIR` | `'repair'` |

#### `StatusTone`

| 枚举成员 / 别名 | 值 |
| --- | --- |
| `NEUTRAL` | `'neutral'` |
| `INFO` | `'info'` |
| `SUCCESS` | `'success'` |
| `ERROR` | `'error'` |

#### `Row`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `values` | `tuple[str, ...]` | `必填` | 表格单行内容 |
| `tag` | `str` | `''` | 表格样式标识 |

#### `WorkbenchState`

| 字段 | 类型 | 默认 / 初始化 | 含义 |
| --- | --- | --- | --- |
| `phase` | `str` | `必填` | 状态机阶段 |
| `tone` | `StatusTone` | `必填` | 呈现色调 |
| `status_title` | `str` | `必填` | 短状态文本 |
| `status_detail` | `str` | `必填` | 状态细节 |
| `source_path` | `str` | `''` | 输入源位置 |
| `workflow` | `WorkflowKind` | `WorkflowKind.UNWRAP` | 提取或修复路线 |
| `rows` | `tuple[Row, ...]` | `()` | 表格行元组 |
| `details` | `tuple[tuple[str, str], ...]` | `()` | 补充信息键值 |
| `logs` | `tuple[str, ...]` | `()` | 日志行 |
| `action_label` | `str` | `'提取'` | 当前按钮文字 |
| `can_act` | `bool` | `False` | 是否允许执行动作 |

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `WorkbenchState.empty(cls) -> 'WorkbenchState'` | 生成初始 empty 状态，不保存已加载对象。 |

#### `ConsoleController`

| 方法 / 属性签名 | 功能、结果与边界 |
| --- | --- |
| `ConsoleController.__init__(self, service: ContainerService &#124; None=None, *, repair_service: RepairService &#124; None=None, recovery_options: dict &#124; None=None) -> None` | 初始化本类状态与注入依赖；资源分配或默认策略按上述模块说明执行。 |
| `ConsoleController.state(self) -> WorkbenchState` | 在锁内取得当前不可变快照。 |
| `ConsoleController.reset(self) -> WorkbenchState` | 清除加载和修复对象，并回到空状态。 |
| `ConsoleController.begin_load(self, path: str &#124; Path) -> WorkbenchState` | 清空旧对象，设置 loading、源名称与一条日志。 |
| `ConsoleController.load(self, path: str &#124; Path) -> WorkbenchState` | 先尝试容器，否则尝试修复，返回更新后的快照。 |
| `ConsoleController._load_repair(self, path: Path) -> WorkbenchState` | 匹配修复配置，并区分无配置的有效引导或无法识别输入。 |
| `ConsoleController._unwrap_state(self, loaded: LoadedProgram) -> WorkbenchState` | 把已加载容器摘要转换为 ready 状态与信息行。 |
| `ConsoleController._fail(self, title: str, detail: str) -> WorkbenchState` | 设置错误状态、消息与日志，并禁用处理动作。 |
| `ConsoleController.begin_action(self) -> WorkbenchState` | 进入 busy 状态并禁用重复执行。 |
| `ConsoleController.act(self, output: str &#124; Path &#124; None=None) -> tuple[WorkbenchState, str &#124; None]` | 根据已加载类型选择提取/修复，返回 (状态, 输出路径或 None)。 |
| `ConsoleController._act_unwrap(self, loaded: LoadedProgram, output: str &#124; Path &#124; None) -> tuple[WorkbenchState, str &#124; None]` | 使用用户输出或默认名提取，反馈区块进度并更新完成/失败状态。 |
| `ConsoleController._act_repair(self, inspection: RepairInspection, output: str &#124; Path &#124; None) -> tuple[WorkbenchState, str &#124; None]` | 转交恢复选项与进度回调，捕获预期错误并展示发布结果。 |
| `ConsoleController._line(message: str) -> str` | 为日志增加当前时间，不改变业务状态。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest tests/test_viewmodel.py tests/test_native_repair.py tests/test_cli.py -q
```

[返回项目总说明](../../README.md)
