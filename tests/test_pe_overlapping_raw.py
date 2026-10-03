"""Regression for oversized protector raw containers overlapping later RVAs."""
from dataclasses import replace

import pytest

from exerepair.formats.enigma import EnigmaFormatError, PEImage, Section


def image():
    return PEImage(
        machine=0x14C, bitness=32, timestamp=0, image_base=0x400000,
        entry_rva=0xE2D7B0, section_alignment=0x1000, file_alignment=0x200,
        size_of_image=0xE31000, size_of_headers=0x400, subsystem=2,
        sections=(
            Section("", 0x713000, 0x506000, 0x35A9E00, 0x1BF800, 0xE0000020),
            Section(".data", 0x218000, 0xC19000, 0x217800, 0x3769600, 0xE0000040),
        ), file_size=0x3980C00,
    )


def test_entry_maps_to_later_section_not_oversized_container():
    pe = image()
    assert pe.rva_to_offset(pe.entry_rva) == 0x397DDB0
    assert pe.section_for_rva(pe.entry_rva).name == ".data"


def test_section_order_does_not_change_mapping():
    pe = image()
    other = replace(pe, sections=tuple(reversed(pe.sections)))
    assert other.rva_to_offset(pe.entry_rva) == pe.rva_to_offset(pe.entry_rva)
    assert other.section_for_rva(pe.entry_rva) == pe.section_for_rva(pe.entry_rva)


def test_container_bytes_before_later_section_keep_original_mapping():
    pe = image()
    assert pe.rva_to_offset(0x507000) == 0x1C0800
    assert pe.section_for_rva(0x507000) == pe.sections[0]


def test_header_mapping_is_unchanged():
    assert image().rva_to_offset(0x3C) == 0x3C


def test_unknown_rva_still_rejected():
    with pytest.raises(EnigmaFormatError):
        image().rva_to_offset(0x500000)
