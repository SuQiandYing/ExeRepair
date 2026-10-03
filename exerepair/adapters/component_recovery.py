"""Bounded recovery of game bytes. Components and key prefixes stay in RAM."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import time
from typing import Callable
import zlib

from ..domain.recovery import RecoveredPayload, RecoveryError
from ..formats.enigma import PEImage


def _primitives():
    try:
        import numba
        import numpy as np
        from .cpu_filter import md5_u32, rc4, scan
    except ImportError as error:
        raise RecoveryError(
            "自动恢复需要运行时依赖；请安装 exerepair[recovery]，"
            "或用 --recovery-manifest 复用已校验载荷"
        ) from error
    numba.set_num_threads(min(8, numba.config.NUMBA_NUM_THREADS))
    for value in (0, 1, 7, 0x12345678, 0xFFFFFFFF):
        if bytes(md5_u32(value)) != hashlib.md5(struct.pack("<I", value)).digest():
            raise RecoveryError("MD5 合成向量失败")
    if bytes(rc4(np.frombuffer(b"Plaintext", dtype=np.uint8),
                 np.frombuffer(b"Key", dtype=np.uint8))).hex() != "bbf316e8d940af0ad3":
        raise RecoveryError("RC4 合成向量失败")
    return np, md5_u32, rc4, scan


def verify_filter(engine, compressor) -> dict:
    """Independent synthetic ranges; no actual activation material is involved."""
    np, md5_u32, rc4, cpu_scan = _primitives()
    fixture = b"".join(hashlib.sha256(struct.pack("<I", i)).digest() for i in range(256))
    packed = compressor(fixture)
    prefix = np.arange(16, dtype=np.uint8)
    for value in (7, 0x12345678, 0xFFFFFFF7):
        start = value & ~255
        key = np.concatenate((prefix, md5_u32(value)))
        cipher = rc4(np.frombuffer(packed, dtype=np.uint8), key)
        cpu = cpu_scan(prefix, cipher[:128], start, 256, len(fixture))
        selected = engine.scan(prefix, cipher[:128], start, 256, len(fixture)) if engine else cpu
        if not np.array_equal(cpu, selected) or selected[value - start] != 1:
            raise RecoveryError("CPU/GPU 结构筛选合成向量不一致")
        matches = [
            int(i) for i in np.flatnonzero(selected)
            if zlib.crc32(bytes(rc4(cipher, np.concatenate(
                (prefix, md5_u32(start + int(i))))))) == zlib.crc32(packed)
        ]
        if matches != [value - start]:
            raise RecoveryError("合成载荷全量 CRC 恢复不唯一")
    return {"synthetic_candidates_compared": 768, "high_bit_range_verified": True}


def recover_payloads(
    original: bytes, profile, context: dict, *,
    backend: str, start: int, count: int,
    progress: Callable[[str], None], work_dir: Path,
) -> tuple[RecoveredPayload, ...]:
    if backend not in ("auto", "cpu", "opencl"):
        raise RecoveryError("搜索后端必须为 auto / cpu / opencl")
    if not (0 <= start < 2**32 and 0 < count <= 2**32 - start):
        raise RecoveryError("搜索范围必须落在 32 位域内")
    if hashlib.sha256(original).hexdigest() != profile.baseline_sha256:
        raise RecoveryError("恢复源身份不匹配")
    np, md5_u32, rc4, cpu_scan = _primitives()
    first = profile.payloads[0]
    rows = [r for r in context.get("descriptors", [])
            if r.get("payload_size", 0) and r.get("flags", 0) & 8]
    by_rva = {r["source_rva"]: r for r in rows}
    if len(rows) != len(profile.payloads) or len(by_rva) != len(rows):
        raise RecoveryError("捕获的非空加密描述符集合不匹配")
    for spec in profile.payloads:
        row = by_rva.get(spec.source_rva)
        if row is None or any(row.get(name) != expected for name, expected in (
            ("payload_size", spec.size), ("flags", spec.flags), ("expected_crc", spec.crc32),
        )):
            raise RecoveryError("捕获的载荷描述符与已验证配置不符")
        prefix = row.get("key_prefix")
        if not isinstance(prefix, list) or len(prefix) != 16 or any(
            not isinstance(v, int) or not 0 <= v < 256 for v in prefix
        ):
            raise RecoveryError("捕获的密钥前缀格式错误")
    cipher_bytes = original[first.source_offset:first.source_offset + first.size]
    if bytes(context.get("ciphertext", [])) != cipher_bytes[:256]:
        raise RecoveryError("捕获的输入不是当前原始载荷")
    if context.get("key_length") != 32 or context.get("hardware_component_enabled") is not False:
        raise RecoveryError("捕获的密钥模式不符合当前已验证配置")
    if first.size < 256 or not first.flags & 1:
        raise RecoveryError("当前结构筛选要求第一载荷为较大的 aPLib 压缩流")
    pe = PEImage.parse(original)
    maximum = pe.section_for_rva(first.source_rva).virtual_size
    prefix = np.array(by_rva[first.source_rva]["key_prefix"], dtype=np.uint8)
    cipher = np.frombuffer(cipher_bytes, dtype=np.uint8)
    engine = None
    try:
        if backend in ("auto", "opencl"):
            try:
                from .opencl_filter import OpenCLFilter
                engine = OpenCLFilter()
            except (OSError, RuntimeError) as error:
                if backend == "opencl":
                    raise RecoveryError(f"指定的 OpenCL 后端不可用：{error}") from error
                progress("OpenCL 不可用，使用有界 CPU 后端（通常较慢）")
        chosen = "opencl" if engine else "cpu"
        from .aplib import AplibCompressor
        verify_filter(engine, AplibCompressor())
        scan = engine.scan if engine else cpu_scan
        step = 1 << 20
        end = start + count
        original_range_start = start
        cursor_path = work_dir / "search-cursor.json"
        if cursor_path.is_file():
            cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
            if (cursor.get("baseline_sha256") == profile.baseline_sha256
                    and cursor.get("range_start") == start and cursor.get("range_end") == end):
                resumed = cursor.get("tested_until_exclusive", start)
                if isinstance(resumed, int) and start <= resumed <= end:
                    start = resumed
        elapsed_start = time.monotonic()
        work_dir.mkdir(parents=True, exist_ok=True)
        for chunk_number, chunk_start in enumerate(range(start, end, step)):
            chunk_count = min(step, end - chunk_start)
            flags = scan(prefix, cipher[:128], chunk_start, chunk_count, maximum)
            for offset in np.flatnonzero(flags):
                # Never print, return or serialize this value or any derived key.
                component = chunk_start + int(offset)
                key = np.concatenate((prefix, md5_u32(component)))
                clear = bytes(rc4(cipher, key))
                if zlib.crc32(clear) != first.crc32:
                    continue
                if hashlib.sha256(clear).hexdigest() != first.clear_sha256:
                    continue
                payloads = []
                for spec in profile.payloads:
                    record_prefix = np.array(by_rva[spec.source_rva]["key_prefix"], dtype=np.uint8)
                    key = np.concatenate((record_prefix, md5_u32(component)))
                    data = np.frombuffer(
                        original[spec.source_offset:spec.source_offset + spec.size], dtype=np.uint8
                    )
                    recovered = bytes(rc4(data, key))
                    if zlib.crc32(recovered) != spec.crc32 or (
                        hashlib.sha256(recovered).hexdigest() != spec.clear_sha256
                    ):
                        raise RecoveryError("候选未通过全部载荷的独立 CRC/SHA 校验")
                    payloads.append(RecoveredPayload(spec, recovered))
                progress(f"已恢复并校验 {len(payloads)} 个载荷；激活值未写入")
                return tuple(payloads)
            checkpoint = {
                "format": "exerepair.search-cursor.v1", "baseline_sha256": profile.baseline_sha256,
                "range_start": original_range_start, "range_end": end,
                "tested_until_exclusive": chunk_start + chunk_count,
                "backend": chosen, "sensitive_values_written": False,
            }
            temporary = cursor_path.with_suffix(".next.json")
            temporary.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
            temporary.replace(cursor_path)
            if chunk_number % 16 == 0:
                progress(
                    f"{chosen} 已检查至 {chunk_start + chunk_count:,}/{end:,}；"
                    f"耗时 {time.monotonic() - elapsed_start:.1f}s"
                )
        raise RecoveryError("指定范围已全部检查，无匹配载荷；未写出修复 EXE，可扩大范围或恢复进度")
    finally:
        if engine:
            engine.close()
