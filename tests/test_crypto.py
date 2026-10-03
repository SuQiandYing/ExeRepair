from exerepair.crypto import RandomV1, crc32, xor_in_place


def test_crc32_reference_vector() -> None:
    assert crc32(b"123456789") == 0xFC891918


def test_random_v1_matches_csharp_reference_vector() -> None:
    random = RandomV1(0x12345678)
    assert [random.move_next() for _ in range(12)] == [
        0x0432E2C2,
        0xDBCE2D4B,
        0x9B6BF0B9,
        0x2B92A50A,
        0x80845352,
        0x20B38E54,
        0x6FB3F5A4,
        0x728A7CB6,
        0xCC290762,
        0x65E017FD,
        0x78770575,
        0x7A864740,
    ]


def test_xor_stream_is_reversible() -> None:
    data = bytearray(range(256)) * 7
    original = bytes(data)
    xor_in_place(data, 0xDEADBEEF)
    assert data != original
    xor_in_place(data, 0xDEADBEEF)
    assert data == original
