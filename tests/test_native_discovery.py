import os
from pathlib import Path

import pytest

from exerepair.domain.recovery import NativeCallProfile, RecoveryError
from exerepair.workflows.native_discovery import (
    bind_runtime_evidence, discover_native_static,
)
from exerepair.workflows.profiles import identify_profile


# Optional developer fixture.  Keep machine-specific locations out of the
# source tree; callers can point at a local sample through an environment
# variable when they have the matching authorized fixture.
TP03 = Path(os.environ.get("EXEREPAIR_TP03_FIXTURE", "fixtures/tp03.exe"))


@pytest.mark.skipif(not TP03.is_file(), reason="local native fixture is unavailable")
def test_unknown_enigma_build_uses_structural_profile_not_game_registry():
    data = TP03.read_bytes()
    profile = identify_profile(data)
    assert isinstance(profile, NativeCallProfile)
    assert profile.requires_runtime_discovery is True
    assert profile.name.startswith("enigma-1.31-native-call-candidate")
    assert profile.dispatch_rva == 0x133AFE
    assert profile.dispatch_global_rva == 0x1BA8A4
    assert profile.engine_base_delta == 0x113000
    assert len(profile.bootstrap_size_offsets) == 2
    assert len(profile.bootstrap_source_offsets) == 2


@pytest.mark.skipif(not TP03.is_file(), reason="local native fixture is unavailable")
def test_runtime_evidence_binds_only_unique_executeapi_call():
    data = TP03.read_bytes()
    static = discover_native_static(data)
    evidence = {
        "signature_rva": 0x1845D,
        "guard_rva": 0x18486,
        "call_rva": 0x1848B,
        "return_rva": 0x1848D,
        "guard_bytes": "68046a4d00ffd083c404",
        "main_base": "0x400000",
        "module_rva": 0xD6A1C,
        "name_rva": 0xD6A10,
        "module_name": "plugin.dll",
        "export": "executeAPI",
        "candidate_count": 1,
    }
    bound = bind_runtime_evidence(static, data, evidence)
    assert bound.requires_runtime_discovery is False
    assert bound.call_rva == 0x1848B
    with pytest.raises(RecoveryError, match="唯一"):
        bind_runtime_evidence(
            static, data, {**evidence, "candidate_count": 2}
        )


def test_static_discovery_rejects_non_enigma_bytes():
    with pytest.raises(RecoveryError):
        discover_native_static(b"not-a-pe")
