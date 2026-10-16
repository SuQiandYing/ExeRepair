from exerepair.api import NATIVE_CALL_X86_V2, NativeCallProfile


def test_tp02_profile_is_available_from_public_api():
    assert isinstance(NATIVE_CALL_X86_V2, NativeCallProfile)
    assert NATIVE_CALL_X86_V2.name == "native-call-x86-v2-enigma-1.31"
    assert NATIVE_CALL_X86_V2.guard_rva == 0x18486
    assert NATIVE_CALL_X86_V2.call_rva == 0x1848B
