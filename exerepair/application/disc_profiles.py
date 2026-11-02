"""Load explicit, bounded configurations for the guarded disc-check builder."""
from __future__ import annotations

import json
from pathlib import Path
import re

from ..domain.recovery import DiscCheckProfile, RecoveryError
from ..workflows.disc_repair import validate_disc_profile


_INTEGER_FIELDS = (
    "baseline_size", "image_base", "entry_rva", "module_image_size",
    "caller_return_rva", "return_rva", "success_flag_rva",
)
_BYTE_FIELDS = ("entry_bytes", "caller_guard", "return_guard")
_REQUIRED = frozenset(("format", "name", "baseline_sha256", *_INTEGER_FIELDS, *_BYTE_FIELDS))
_OPTIONAL = frozenset(("allow_dynamic_base_without_relocations", "runtime_note"))
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_HEX_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+\Z")


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise RecoveryError(f"外部光盘配置包含重复字段：{name}")
        result[name] = value
    return result


def _uint32(name: str, value: object) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and _HEX_NUMBER.fullmatch(value):
        result = int(value, 16)
    else:
        raise RecoveryError(f"外部光盘配置字段必须为整数或十六进制字符串：{name}")
    if not 0 <= result <= 0xFFFFFFFF:
        raise RecoveryError(f"外部光盘配置整数超出 32 位范围：{name}")
    return result


def _hex_bytes(name: str, value: object) -> bytes:
    if (
        not isinstance(value, str)
        or not 2 <= len(value) <= 512
        or len(value) % 2
        or not _HEX.fullmatch(value)
    ):
        raise RecoveryError(f"外部光盘配置字段必须为非空十六进制字节：{name}")
    return bytes.fromhex(value)


def load_disc_profile(path: str | Path) -> DiscCheckProfile:
    """Load a scalar disc-check configuration without registering it globally."""
    source = Path(path).expanduser().resolve(strict=True)
    with source.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise RecoveryError("外部光盘配置超过大小限制")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_fields)
    except RecoveryError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise RecoveryError("外部光盘配置不是有效的 UTF-8 JSON") from error
    if not isinstance(data, dict):
        raise RecoveryError("外部光盘配置根节点必须是对象")
    missing = _REQUIRED - data.keys()
    unknown = data.keys() - _REQUIRED - _OPTIONAL
    if missing or unknown:
        raise RecoveryError(
            f"外部光盘配置字段不匹配：缺少 {sorted(missing)}；未知 {sorted(unknown)}"
        )
    if data["format"] != "exerepair.disc-profile.v1":
        raise RecoveryError("不支持的外部光盘配置格式")
    name = data["name"]
    digest = data["baseline_sha256"]
    note = data.get("runtime_note", "")
    dynamic = data.get("allow_dynamic_base_without_relocations", False)
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise RecoveryError("外部光盘配置名称无效")
    if not isinstance(digest, str) or len(digest) != 64 or not _HEX.fullmatch(digest):
        raise RecoveryError("外部光盘配置 SHA-256 无效")
    if not isinstance(note, str) or len(note) > 2048:
        raise RecoveryError("外部光盘配置运行提示无效")
    if type(dynamic) is not bool:
        raise RecoveryError("外部光盘配置动态基址选项必须是布尔值")
    integers = {field: _uint32(field, data[field]) for field in _INTEGER_FIELDS}
    if integers["baseline_size"] == 0:
        raise RecoveryError("外部光盘配置输入长度必须大于零")
    encoded = {field: _hex_bytes(field, data[field]) for field in _BYTE_FIELDS}
    profile = DiscCheckProfile(
        name=name,
        baseline_sha256=digest.lower(),
        **integers,
        **encoded,
        allow_dynamic_base_without_relocations=dynamic,
        runtime_note=note,
    )
    validate_disc_profile(profile)
    return profile
