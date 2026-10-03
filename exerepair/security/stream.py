"""Container V1's deterministic XOR stream."""

from __future__ import annotations

_UINT32_MASK = 0xFFFFFFFF


class RandomV1:
    """521-word generator retained as a small, independently testable policy."""

    __slots__ = ("_position", "_data")

    def __init__(self, seed: int = 0) -> None:
        self._position = 0
        self._data = [0] * 521
        self._initialize(seed & _UINT32_MASK)

    def _initialize(self, seed: int) -> None:
        data = self._data
        for index in range(17):
            value = 0
            for _ in range(32):
                seed = (seed * 0x5D588B65 + 1) & _UINT32_MASK
                value = (value >> 1) | (seed & 0x80000000)
            data[index] = value

        data[16] = (
            data[15] ^ (data[0] >> 9) ^ ((data[16] << 23) & _UINT32_MASK)
        ) & _UINT32_MASK
        for index in range(504):
            data[index + 17] = (
                data[index + 16]
                ^ (data[index + 1] >> 9)
                ^ ((data[index] << 23) & _UINT32_MASK)
            ) & _UINT32_MASK

        self._transform()
        self._transform()
        self._transform()
        self._position = 520

    def _transform(self) -> None:
        data = self._data
        for index in range(32):
            data[index] ^= data[index + 489]
        for index in range(489):
            data[index + 32] ^= data[index]

    def move_next(self) -> int:
        position = self._position + 1
        if position >= 521:
            self._transform()
            position = 0
        self._position = position
        return self._data[position]

    def MoveNext(self) -> int:
        return self.move_next()


def xor_in_place(data: bytearray | memoryview, key: int) -> None:
    view = memoryview(data).cast("B")
    if view.readonly:
        raise TypeError("data must be writable")
    random = RandomV1(key)
    move_next = random.move_next
    for index in range(len(view)):
        view[index] ^= move_next() & 0xFF
