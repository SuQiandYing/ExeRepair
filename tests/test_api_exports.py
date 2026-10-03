from exerepair.api import EXHIBIT_DMM_TP02, NativeCallProfile


def test_tp02_profile_is_available_from_public_api():
    assert isinstance(EXHIBIT_DMM_TP02, NativeCallProfile)
    assert EXHIBIT_DMM_TP02.name == "exhibit-hoshizora-tp02-dmm-enigma-1.31"
    assert EXHIBIT_DMM_TP02.guard_rva == 0x18486
    assert EXHIBIT_DMM_TP02.call_rva == 0x1848B
