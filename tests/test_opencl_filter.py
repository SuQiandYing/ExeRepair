"""Host allocation/lifecycle tests without requiring a GPU or recovery runtime."""
from __future__ import annotations

import ctypes as C

import pytest


def make_filter():
    np = pytest.importorskip("numpy")
    from exerepair.adapters.opencl_filter import P, U, OpenCLFilter

    class FakeOpenCL:
        def __init__(self):
            self.buffers = {}
            self.created = []
            self.released = []
            self.writes = []
            self.arguments = {}
            self.handle = 100

        def clCreateBuffer(self, _context, flags, size, data, error):
            C.cast(error, C.POINTER(C.c_int32)).contents.value = 0
            self.handle += 1
            self.created.append((self.handle, flags, size))
            self.buffers[self.handle] = bytearray(C.string_at(data, size) if data else bytes(size))
            return self.handle

        def clEnqueueWriteBuffer(self, _queue, buffer, blocking, offset, size, data, *_):
            assert blocking == 1
            assert offset + size <= len(self.buffers[buffer])
            self.buffers[buffer][offset:offset + size] = C.string_at(data, size)
            self.writes.append(buffer)
            return 0

        def clSetKernelArg(self, _kernel, index, _size, data):
            kind = P if index in (0, 1, 5) else U
            self.arguments[index] = C.cast(data, C.POINTER(kind)).contents.value
            return 0

        def clEnqueueNDRangeKernel(self, _queue, _kernel, _dimension, _offset,
                                   global_size, local_size, *_):
            size = C.cast(global_size, C.POINTER(C.c_size_t)).contents.value
            local = C.cast(local_size, C.POINTER(C.c_size_t)).contents.value
            args = self.arguments
            assert size >= args[3] and size % local == 0
            prefix = self.buffers[args[0]][0]
            cipher = self.buffers[args[1]][0]
            output = self.buffers[args[5]]
            for i in range(args[3]):
                output[i] = (prefix ^ cipher ^ (args[2] + i)) & 1
            return 0

        def clEnqueueReadBuffer(self, _queue, buffer, blocking, offset, size, destination, *_):
            assert blocking == 1
            assert offset + size <= len(self.buffers[buffer])
            C.memmove(destination, bytes(self.buffers[buffer][offset:offset + size]), size)
            return 0

        def clReleaseMemObject(self, buffer):
            assert buffer in self.buffers
            del self.buffers[buffer]
            self.released.append(buffer)
            return 0

        def clReleaseContext(self, _context):
            return 0

    engine = OpenCLFilter.__new__(OpenCLFilter)
    engine.lib = FakeOpenCL()
    engine.context, engine.queue, engine.kernel = 1, 2, 3
    engine.owned = [("clReleaseContext", engine.context)]
    engine._input_buffers = []
    engine._input_values = None
    engine._output_buffer = None
    engine._output_capacity = 0
    engine.local_size = 32
    return engine, np


def test_buffers_reused_changed_inputs_uploaded_and_growth_released():
    engine, np = make_filter()
    prefix = np.arange(16, dtype=np.uint8)
    cipher = np.arange(128, dtype=np.uint8)
    try:
        first = engine.scan(prefix, cipher, 7, 17, 8192)
        assert first.tolist() == [(7 + i) & 1 for i in range(17)]
        assert len(engine.lib.created) == 3
        second = engine.scan(prefix.copy(), cipher.copy(), 11, 8, 8192)
        assert second.tolist() == [(11 + i) & 1 for i in range(8)]
        assert len(engine.lib.created) == 3 and not engine.lib.writes
        old_output = engine._output_buffer
        prefix[0] = 1
        third = engine.scan(prefix, cipher, 11, 65, 8192)
        assert third.tolist() == [(1 ^ (11 + i)) & 1 for i in range(65)]
        assert len(engine.lib.created) == 4
        assert len(engine.lib.writes) == 2
        assert engine.lib.released == [old_output]
        assert len(engine.lib.buffers) == 3
    finally:
        engine.close()
    assert not engine.lib.buffers and not engine.owned
    assert len(engine.lib.released) == 4
    assert engine._input_values is None
    engine.close()
    with pytest.raises(RuntimeError, match="closed"):
        engine.scan(prefix, cipher, 0, 1, 8192)


@pytest.mark.parametrize("start,count", [
    (-1, 1), (2**32, 1), (2**32 - 1, 2), (0, 0), (0, (1 << 23) + 1),
])
def test_invalid_ranges_allocate_nothing(start, count):
    engine, np = make_filter()
    try:
        with pytest.raises(ValueError, match="bounded"):
            engine.scan(np.arange(16, dtype=np.uint8), np.zeros(128, dtype=np.uint8),
                        start, count, 8192)
        assert not engine.lib.created
    finally:
        engine.close()


@pytest.mark.parametrize("case", ["prefix", "cipher", "shape", "bound"])
def test_invalid_inputs_allocate_nothing(case):
    engine, np = make_filter()
    prefix, cipher, maximum = np.arange(16, dtype=np.uint8), np.zeros(128, dtype=np.uint8), 8192
    if case == "prefix":
        prefix = prefix[:15]
    elif case == "cipher":
        cipher = cipher[:127]
    elif case == "shape":
        prefix = prefix.reshape(16, 1)
    else:
        maximum = 0
    try:
        with pytest.raises(ValueError):
            engine.scan(prefix, cipher, 0, 1, maximum)
        assert not engine.lib.created
    finally:
        engine.close()
