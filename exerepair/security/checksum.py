"""The non-reflected CRC32 variant used in Container headers."""

from __future__ import annotations

_UINT32_MASK = 0xFFFFFFFF
_CRC_POLYNOMIAL = 0x04C11DB7


def _build_crc_table() -> tuple[int, ...]:
    table: list[int] = []
    for value in range(256):
        crc = value << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ _CRC_POLYNOMIAL) & _UINT32_MASK
            else:
                crc = (crc << 1) & _UINT32_MASK
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _build_crc_table()


def crc32(data: bytes | bytearray | memoryview) -> int:
    crc = _UINT32_MASK
    for value in memoryview(data).cast("B"):
        crc = _CRC_TABLE[value ^ (crc >> 24)] ^ ((crc << 8) & _UINT32_MASK)
    return (~crc) & _UINT32_MASK


class CRC32:
    """Compatibility facade and named checksum policy."""

    @staticmethod
    def hash(data: bytes | bytearray | memoryview) -> int:
        return crc32(data)

    @staticmethod
    def Hash(data: bytes | bytearray | memoryview) -> int:
        return crc32(data)
