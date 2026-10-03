"""Verified build identities, never guessed offsets for arbitrary Enigma EXEs."""
from __future__ import annotations

import hashlib

from ..domain.recovery import NativeCallProfile, PayloadSpec, RecoveryError, RepairProfile


TAYUTAMA_ZERO = RepairProfile(
    name="tayutama-zero-dl-enigma-1.31",
    baseline_sha256="a94e0f2a34c365f6238e6734e6bf9cb5574560c2bd26faacf1b826c49e7658f1",
    baseline_size=4116480,
    engine_sha256="83d225829cea4dc9b0e73329a2ddedae538cdfef196f1a243d5fdb7fb3fee5fa",
    engine_base_delta=0x42D000,
    vm_table_offset=0x791FAA,
    vm_table_count=33905,
    payloads=(
        PayloadSpec(4096, 1536, 1207451, 15, 2386725812,
                    "e600a805bbf6c4416dca044d748b548553712ad438b82d5c211ea62908062b02"),
        PayloadSpec(3268608, 1209344, 9110, 11, 1758501764,
                    "6131a09dfa91a79aab113ab6bfad7f3d17c321b037966a7df2ee392a6a117064"),
        PayloadSpec(3301376, 1218560, 33446, 11, 775858994,
                    "68d58006fbc32b5532f1efa7ba4d4770246649d300918d9e6922267786d9c60c"),
        PayloadSpec(3473408, 1252352, 132, 11, 1248253033,
                    "d8056376396417b7264e07b3a2d4fdd254aab00e41fa45a28197abb28e3065a7"),
        PayloadSpec(3489792, 1252864, 393, 11, 3413823467,
                    "29252fcb6c63b94eb1e8e77a075a2cc0d0a77a36e9f3e67976bde3954eaebb81"),
        PayloadSpec(3502080, 1253376, 144971, 11, 3999195933,
                    "7256c2ad10766b289499267049c40e306c3b4f64262949157b9a1ea0350904ec"),
        PayloadSpec(3747840, 1398784, 29370, 11, 2304045156,
                    "cdf7545b3026bd8ad76c87e5f50f0196fc3fa65824c6bc620507b0f886ccb166"),
    ),
)
EXHIBIT_DMM = NativeCallProfile(
    name="exhibit-hoshizora-tp01-dmm-enigma-1.31",
    baseline_sha256="a903a9d97b62d3d52fb62a1f648f836384b41dd089afd967808ab8f7808a2a82",
    baseline_size=3186688,
    engine_sha256="06635a974b4818d93bedd02f0d2422d56b38ca6140dcde014841fc34aec9557e",
    engine_base_delta=0x101000,
    dispatch_rva=0x133AFE,
    dispatch_global_rva=0x1BA8A4,
    relocation_offset=0x685C08,
    guard_rva=0x183B6,
    call_rva=0x183BB,
    guard_bytes=bytes.fromhex("68044a4c00ffd083c404"),
    bootstrap_size_offsets=(121, 196),
    bootstrap_source_offsets=(126, 201),
)
PROFILES = (TAYUTAMA_ZERO, EXHIBIT_DMM)


def identify_profile(data: bytes) -> RepairProfile | NativeCallProfile:
    digest = hashlib.sha256(data).hexdigest()
    for profile in PROFILES:
        if digest == profile.baseline_sha256 and len(data) == profile.baseline_size:
            return profile
    raise RecoveryError(
        "没有匹配的已验证单样本配置；拒绝把其他版本的 VM 偏移套用到此文件。"
        "新版本需单独分析并建立经过验证的配置。"
    )
