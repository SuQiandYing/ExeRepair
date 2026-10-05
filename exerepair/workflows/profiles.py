"""Fast-path identities plus structural fallback for supported Enigma families."""
from __future__ import annotations

import hashlib

from ..domain.recovery import (
    DiscCheckProfile, NativeCallProfile, PayloadSpec, RecoveryError, RepairProfile,
)
from .native_discovery import discover_native_static


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
EXHIBIT_DMM_TP02 = NativeCallProfile(
    name="exhibit-hoshizora-tp02-dmm-enigma-1.31",
    baseline_sha256="fd3d7901556afc9d82afa23103a05ab2e81050dabeae2e2ed164b345d642c339",
    baseline_size=6483968,
    engine_sha256="756b5c0a14107f47b298f5ac6a5ef526dc30da682cf082cd671dade0ed9e3381",
    engine_base_delta=0x113000,
    dispatch_rva=0x133AFE,
    dispatch_global_rva=0x1BA8A4,
    relocation_offset=0x686C08,
    guard_rva=0x18486,
    call_rva=0x1848B,
    guard_bytes=bytes.fromhex("68046a4d00ffd083c404"),
    bootstrap_size_offsets=(121, 198),
    bootstrap_source_offsets=(126, 203),
)
DISC_CHECK_X86_V1 = DiscCheckProfile(
    name="disc-check-x86-v1",
    baseline_sha256="0ebcb11b167746b907dd5c7b2d8b972275308164e888ea720d87f858d5f19496",
    baseline_size=5521408,
    image_base=0x400000,
    entry_rva=0x1ACFD3,
    entry_bytes=bytes.fromhex(
        "52ba6400000085d2741db90010000085c9740701c801d849ebf5525454"
        "ff1541d1b5045a4aebdf5ae900d0cb04"
    ),
    module_image_size=0x574000,
    caller_return_rva=0xF2CA,
    caller_guard=bytes.fromhex("9083f8050f8567010000"),
    return_rva=0xC155,
    return_guard=bytes.fromhex("8b45e88b4df464890d000000008be55dc3"),
    success_flag_rva=0x309F8,
)
DISC_CHECK_X86_V2 = DiscCheckProfile(
    name="disc-check-x86-v2",
    baseline_sha256="422b73af3108c61c793aabefd7221b677ae81058bf6e0cab328b35e7a766fbdb",
    baseline_size=5659136,
    image_base=0x400000,
    entry_rva=0x5017000,
    entry_bytes=bytes.fromhex(
        "6800000000680100000068000040006800604105e9000400000422000000000000"
        "c621000000000000a2210000"
    ),
    module_image_size=0x57A000,
    caller_return_rva=0xFA13,
    caller_guard=bytes.fromhex("9083f8050f8567010000"),
    return_rva=0xC160,
    return_guard=bytes.fromhex("8b45e88b4df464890d000000008be55dc3"),
    success_flag_rva=0x309D8,
    region_ready_rva=0x5A5F0,
    region_ready_bytes=bytes.fromhex("558bec"),
    region_patch_sites=(
        # The late-loaded SiglusEngine disc gate branches to the MessageBoxW
        # path when the runtime scan returns false.  Redirect that branch to
        # its existing success continuation; the surrounding scan remains
        # intact and no image/drive is required.
        (0x50B51, bytes.fromhex("0f852d010000"), bytes.fromhex("e92e01000090")),
        (0x5AC7E, bytes.fromhex("e86df9ffff"), bytes.fromhex("e98d020000")),
        (0x5AC85, bytes.fromhex("0f8594000000"), bytes.fromhex("e99500000090")),
        (0x5AD26, bytes.fromhex("0f85ed000000"), bytes.fromhex("e9ee00000090")),
        (0x5AE20, bytes.fromhex("0f85ea000000"), bytes.fromhex("e9eb00000090")),
    ),
    allow_dynamic_base_without_relocations=True,
)
PROFILES = (
    TAYUTAMA_ZERO,
    EXHIBIT_DMM,
    EXHIBIT_DMM_TP02,
    DISC_CHECK_X86_V1,
    DISC_CHECK_X86_V2,
)


def identify_profile(data: bytes) -> RepairProfile | NativeCallProfile | DiscCheckProfile:
    digest = hashlib.sha256(data).hexdigest()
    for profile in PROFILES:
        if digest == profile.baseline_sha256 and len(data) == profile.baseline_size:
            return profile
    try:
        return discover_native_static(data)
    except RecoveryError as error:
        raise RecoveryError(
            "没有匹配的已验证配置，且未能从样本结构建立通用 Enigma 原生调用候选。"
        ) from error
