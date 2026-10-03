import pytest

from exerepair.pe import PEFile, PEFormatError
from tests.helpers import make_pe


@pytest.mark.parametrize("bitness", [32, 64])
def test_parse_pe_and_convert_rva(bitness: int) -> None:
    image = make_pe(bitness)
    pe = PEFile.from_bytes(image)
    assert pe.bitness == bitness
    assert pe.overlay_data_file_offset == len(image)
    assert pe.rva_to_foa(0x1080) == 0x280
    assert pe.rva_to_foa(0x100) == 0x100
    assert str(pe) == f"PE{bitness}"


def test_expected_bitness_is_enforced() -> None:
    with pytest.raises(PEFormatError):
        PEFile.from_bytes(make_pe(64), expected_bitness=32)


@pytest.mark.parametrize("image", [b"", b"MZ", b"MZ" + b"\0" * 100])
def test_reject_invalid_or_truncated_pe(image: bytes) -> None:
    with pytest.raises(PEFormatError):
        PEFile.from_bytes(image)
