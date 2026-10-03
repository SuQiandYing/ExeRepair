# 测试夹具、回归分组与边界

本目录用 pytest 验证格式、算法、构建、资源生命周期和控制器。
`helpers.py` 构造小型 PE、容器和加密资源，不依赖个人电脑上的 EXE 路径。

## 覆盖矩阵

| 文件 | 验证功能 |
| --- | --- |
| `test_application.py` | 加载/结果对象、类型化错误、服务接口 |
| `test_architecture.py` | 领域、安全、格式和应用层的依赖方向 |
| `test_cli.py` | 退出码、输出、目标单文件路由、显式选项 |
| `test_crypto.py` | CRC 参考值、序列参考向量、XOR 往返 |
| `test_pe.py` | PE32/PE64、位数约束、截断与非法结构 |
| `test_pe_overlapping_raw.py` | 重叠 RawSize、节表顺序、头部及未知 RVA |
| `test_stub.py` | 所有支持版本、CRC/版本错误、签名变换和位标记显示 |
| `test_program.py` | 内嵌/外置主程序、多资源区块、失败签名和错误信息 |
| `test_runtime_repair.py` | BCJ、补丁范围、清单 CRC/SHA、别名、事务重读、依赖延迟加载、helper 现场/栈 |
| `test_native_repair.py` | 跳板保护、寄存器/标志、重定位块、PE 约束、服务与 CLI/GUI 分流 |
| `test_opencl_filter.py` | 合成后端缓冲区复用、输入更新、扩容释放、无效输入 |
| `test_viewmodel.py` | 状态转换、错误状态和自定义输出 |

## 执行

在项目根目录运行：

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m pytest tests/test_stub.py -q
python -m pytest tests/test_runtime_repair.py -k manifest -q
python -m ruff check exerepair tests tools
```

测试通过 `tmp_path` 使用临时文件，通过 monkeypatch 和合成适配器隔离外部依赖。
测试函数的参数表示 pytest 夹具或参数化输入，不是产品 CLI 参数。
参数化用例会展开为多个测试项，因此函数数量与执行测试数量不同。
机器码验证需要其测试声明的 Unicorn 环境，部分验证在独立子进程中执行。

## 验收范围

合成测试不自动证明实际目标程序启动、所有资源存在、GPU 驱动可用或 GUI 布局完整。
真实运行与回滚需要分别记录输入摘要、同一操作输入、退出原因和可见结果。
更改功能时保留对应回归；文档或显示名称更新不改变既有算法断言。

## 模块、类型与逐项接口

以下签名来自当前源码，包括私有辅助函数和兼容接口。类型注解未声明的接口按上方功能流程解释；属性读取不产生文件输出。表中明确抛出的异常不穷尽依赖调用可能向上传播的异常。

### `__init__.py`

空的包标记文件，使测试目录能使用包内相对导入；不定义接口或执行测试。

### `helpers.py`

合成 PE、容器和加密资源的构造工具。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `make_pe(bitness: int=32, raw_size: int=1024) -> bytearray` | 构建指定32/64位和原始节大小的合成PE缓冲区。 |
| `encrypted_resource(payload: bytes, position: int, signature1: int, signature2: int) -> bytes` | 用指定位置与签名构造可往返的合成资源区块。 明确抛出：`ValueError`。 |
| `_write_c_string(target: memoryview, value: str) -> None` | 把合成名称写为以NUL终止的CP932字段。 明确抛出：`ValueError`。 |
| `make_stub(version: int, mode: int, patches: list[dict[str, int &#124; str]] &#124; None=None, executable_name: str='', key: int=324478056) -> tuple[bytes, int]` | 按给定版本、模式、补丁与key创建配置和对齐尺寸。 明确抛出：`ValueError`。 |
| `make_embedded_wrapper(stub: bytes, align_size: int, executable: bytes) -> bytes` | 拼接外壳PE、配置与内嵌主程序，用于临时文件测试。 |
| `make_external_wrapper(stub: bytes) -> bytes` | 生成只包含配置的外壳，由测试另外准备外置主程序。 |


### `test_application.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_wrapper(tmp_path: Path) -> Path` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_service_returns_immutable_load_and_result_objects(tmp_path) -> None` | 回归检查：service returns immutable load and result objects。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_service_uses_typed_error_codes(tmp_path) -> None` | 回归检查：service uses typed error codes。参数由pytest夹具或参数化提供；断言失败即该项失败。 明确抛出：`AssertionError`。 |


### `test_architecture.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_imports(path: Path) -> set[str]` | 通过AST读取导入边界，为架构测试返回模块名集合。 |
| `test_domain_and_security_do_not_depend_on_outer_layers() -> None` | 回归检查：domain and security do not depend on outer layers。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_formats_never_depend_on_application_or_presentation() -> None` | 回归检查：formats never depend on application or presentation。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_application_has_no_tk_dependency() -> None` | 回归检查：application has no tk dependency。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_cli.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_wrapper(tmp_path: Path) -> Path` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_cli_exit_codes_and_output(tmp_path, capsys) -> None` | 回归检查：cli exit codes and output。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_cli_target_only_route_and_explicit_options(tmp_path, monkeypatch, capsys)` | 回归检查：cli target only route and explicit options。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_crypto.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `test_crc32_reference_vector() -> None` | 回归检查：crc32 reference vector。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_random_v1_matches_csharp_reference_vector() -> None` | 回归检查：random v1 matches csharp reference vector。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_xor_stream_is_reversible() -> None` | 回归检查：xor stream is reversible。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_native_repair.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_verify_native_guard(mismatch)` | 在独立合成机器码执行环境中检查对应保护、寄存器/标志或栈行为，并返回子进程验收结果。 |
| `test_native_trampoline_exact_guard_and_register_flag_preservation(mismatch)` | 回归检查：native trampoline exact guard and register flag preservation。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_trampoline_rejects_unbound_call_shape()` | 回归检查：trampoline rejects unbound call shape。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `relocation_fixture()` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_retired_highlow_relocation_is_checked_inside_its_block()` | 回归检查：retired highlow relocation is checked inside its block。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_wrong_relocation_is_not_silently_retired(damage)` | 回归检查：wrong relocation is not silently retired。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_native_builder_rejects_other_build_without_loading_compressor()` | 回归检查：native builder rejects other build without loading compressor。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_native_builder_checks_pe_constraints_before_engine_processing(damage)` | 回归检查：native builder checks pe constraints before engine processing。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_native_service_uses_static_branch_and_common_transaction(tmp_path, monkeypatch)` | 回归检查：native service uses static branch and common transaction。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_cli_native_inspection_does_not_advertise_payload_search(tmp_path, monkeypatch, capsys)` | 回归检查：cli native inspection does not advertise payload search。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_gui_native_inspection_has_correct_workflow_and_method(tmp_path)` | 回归检查：gui native inspection has correct workflow and method。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_opencl_filter.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `make_filter()` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_buffers_reused_changed_inputs_uploaded_and_growth_released()` | 回归检查：buffers reused changed inputs uploaded and growth released。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_invalid_ranges_allocate_nothing(start, count)` | 回归检查：invalid ranges allocate nothing。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_invalid_inputs_allocate_nothing(case)` | 回归检查：invalid inputs allocate nothing。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_pe.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `test_parse_pe_and_convert_rva(bitness: int) -> None` | 回归检查：parse pe and convert rva。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_expected_bitness_is_enforced() -> None` | 回归检查：expected bitness is enforced。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_reject_invalid_or_truncated_pe(image: bytes) -> None` | 回归检查：reject invalid or truncated pe。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_pe_overlapping_raw.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `image()` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_entry_maps_to_later_section_not_oversized_container()` | 回归检查：entry maps to later section not oversized container。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_section_order_does_not_change_mapping()` | 回归检查：section order does not change mapping。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_container_bytes_before_later_section_keep_original_mapping()` | 回归检查：container bytes before later section keep original mapping。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_header_mapping_is_unchanged()` | 回归检查：header mapping is unchanged。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_unknown_rva_still_rejected()` | 回归检查：unknown rva still rejected。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_program.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_place_block(image: bytearray, offset: int, block: bytes) -> None` | 在合成字节缓冲区给定位置写入区块，供资源提取测试使用。 |
| `test_embedded_executable_and_multiple_resource_patches(tmp_path) -> None` | 回归检查：embedded executable and multiple resource patches。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_external_executable_mode(tmp_path) -> None` | 回归检查：external executable mode。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_executable_only_patch_and_failed_signature(tmp_path) -> None` | 回归检查：executable only patch and failed signature。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_load_error_messages_are_stable(tmp_path) -> None` | 回归检查：load error messages are stable。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_runtime_repair.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `fixture()` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `patch_fixture()` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_bcj_round_trip_and_no_input_mutation(data)` | 回归检查：bcj round trip and no input mutation。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_bcj_known_absolute_and_indirect_deltas()` | 回归检查：bcj known absolute and indirect deltas。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_patch_replay_preserves_baseline()` | 回归检查：patch replay preserves baseline。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_patch_rejects_invalid_ranges_and_identities(case)` | 回归检查：patch rejects invalid ranges and identities。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_payload_manifest_recomputes_crc_and_hash(tmp_path)` | 回归检查：payload manifest recomputes crc and hash。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_legacy_enabled_field_is_not_used_as_destination(tmp_path)` | 回归检查：legacy enabled field is not used as destination。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_wrong_manifest_identity_and_duplicate_are_rejected(tmp_path)` | 回归检查：wrong manifest identity and duplicate are rejected。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_malformed_manifest_is_a_typed_error_not_a_worker_crash(tmp_path, kind)` | 回归检查：malformed manifest is a typed error not a worker crash。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_payload_validation_fails_closed(case)` | 回归检查：payload validation fails closed。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_unknown_build_does_not_get_guessed_offsets()` | 回归检查：unknown build does not get guessed offsets。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_service_keeps_original_and_reopens_transaction_roles(tmp_path, monkeypatch)` | 回归检查：service keeps original and reopens transaction roles。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_service_rejects_source_and_hardlink_alias(tmp_path, monkeypatch)` | 回归检查：service rejects source and hardlink alias。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_regular_import_does_not_load_optional_recovery_dependencies()` | 回归检查：regular import does not load optional recovery dependencies。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_complete_unmodified_native_distribution_is_packaged()` | 回归检查：complete unmodified native distribution is packaged。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `_verify_helper(mode)` | 在独立合成机器码执行环境中检查对应保护、寄存器/标志或栈行为，并返回子进程验收结果。 |
| `test_native_helper_registers_flags_copy_and_stack(mode)` | 回归检查：native helper registers flags copy and stack。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_helper_rejects_empty_or_duplicate_table()` | 回归检查：helper rejects empty or duplicate table。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_stub.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `test_parse_every_supported_stub_version(version: int, level: ContainerVersion) -> None` | 回归检查：parse every supported stub version。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_stub_hash_and_version_errors() -> None` | 回归检查：stub hash and version errors。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_decrypt_resource_checks_and_restores_signature() -> None` | 回归检查：decrypt resource checks and restores signature。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_flag_text_matches_dotnet_style() -> None` | 回归检查：flag text matches dotnet style。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


### `test_viewmodel.py`

该文件的验证目的见上方覆盖矩阵；以下列出全部测试和合成辅助入口。

| 函数签名 | 功能、结果与边界 |
| --- | --- |
| `_wrapper(tmp_path: Path) -> Path` | 构造本模块专用的合成输入/替身；供紧随其后的测试复用，不读取真实程序或配置。 |
| `test_controller_unwrap_flow(tmp_path) -> None` | 回归检查：controller unwrap flow。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_controller_error_state_is_stable(tmp_path) -> None` | 回归检查：controller error state is stable。参数由pytest夹具或参数化提供；断言失败即该项失败。 |
| `test_controller_target_only_flow_respects_custom_output(tmp_path) -> None` | 回归检查：controller target only flow respects custom output。参数由pytest夹具或参数化提供；断言失败即该项失败。 |


## 对应验证

以下命令从项目根目录执行。

```powershell
python -m pytest -q
```

[返回项目总说明](../README.md)
