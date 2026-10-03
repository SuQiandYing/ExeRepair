"""OpenCL structural filter; target-derived bytes never leave process memory.

Bindings follow the Khronos OpenCL 1.2 C API. The standalone test uses only
synthetic fixtures, including high-bit candidate ranges.
"""

from __future__ import annotations

import ctypes as C
from pathlib import Path

import numpy as np

P = C.c_void_p
U = C.c_uint32
L = C.c_uint64
STATUS = C.c_int32
Z = C.c_size_t


class OpenCLFilter:
    def __init__(self):
        self.lib = C.WinDLL("OpenCL.dll")
        self.owned = []
        self._input_buffers = []
        self._input_values = None
        self._output_buffer = None
        self._output_capacity = 0
        self._bind()
        try:
            self._initialize()
        except Exception:
            self.close()
            raise

    def _initialize(self):
        platforms_count = U()
        self.check(self.lib.clGetPlatformIDs(0, None, C.byref(platforms_count)))
        platforms = (P * platforms_count.value)()
        self.check(self.lib.clGetPlatformIDs(len(platforms), platforms, None))
        choices = []
        for platform in platforms:
            count = U()
            status = self.lib.clGetDeviceIDs(platform, 4, 0, None, C.byref(count))
            if status == -1:
                continue
            self.check(status)
            devices = (P * count.value)()
            self.check(
                self.lib.clGetDeviceIDs(platform, 4, len(devices), devices, None)
            )
            for device in devices:
                name = self.info(self.lib.clGetDeviceInfo, device, 0x102B)
                vendor = self.info(self.lib.clGetDeviceInfo, device, 0x102C)
                choices.append(("NVIDIA" not in vendor.upper(), platform, device, name))
        if not choices:
            raise RuntimeError("No enabled OpenCL GPU device")
        _, self.platform, self.device, self.device_name = sorted(
            choices, key=lambda choice: (choice[0], choice[3])
        )[0]
        properties = (C.c_ssize_t * 3)(0x1084, self.platform, 0)
        device_arg = P(self.device)
        error = STATUS()
        self.context = self.lib.clCreateContext(
            properties, 1, C.byref(device_arg), None, None, C.byref(error)
        )
        self.check(error.value)
        self.owned.append(("clReleaseContext", self.context))
        self.queue = self.lib.clCreateCommandQueue(
            self.context, self.device, 0, C.byref(error)
        )
        self.check(error.value)
        self.owned.append(("clReleaseCommandQueue", self.queue))
        source = Path(__file__).with_name("component_prefix.cl").read_bytes()
        source_arg = C.c_char_p(source)
        size = Z(len(source))
        self.program = self.lib.clCreateProgramWithSource(
            self.context, 1, C.byref(source_arg), C.byref(size), C.byref(error)
        )
        self.check(error.value)
        self.owned.append(("clReleaseProgram", self.program))
        status = self.lib.clBuildProgram(
            self.program, 1, C.byref(device_arg), b"-cl-std=CL1.2", None, None
        )
        if status:
            length = Z()
            self.lib.clGetProgramBuildInfo(
                self.program, self.device, 0x1183, 0, None, C.byref(length)
            )
            log = C.create_string_buffer(length.value)
            self.lib.clGetProgramBuildInfo(
                self.program, self.device, 0x1183, len(log), log, None
            )
            raise RuntimeError(
                f"OpenCL build status {status}: "
                + log.value.decode("utf-8", errors="replace")
            )
        self.kernel = self.lib.clCreateKernel(self.program, b"filter", C.byref(error))
        self.check(error.value)
        self.owned.append(("clReleaseKernel", self.kernel))
        maximum = Z()
        self.check(
            self.lib.clGetKernelWorkGroupInfo(
                self.kernel,
                self.device,
                0x11B0,
                C.sizeof(maximum),
                C.byref(maximum),
                None,
            )
        )
        preferred = Z()
        self.check(
            self.lib.clGetKernelWorkGroupInfo(
                self.kernel, self.device, 0x11B3, C.sizeof(preferred),
                C.byref(preferred), None,
            )
        )
        # A full preferred subgroup avoids the old fixed 128-thread assumption.
        self.local_size = min(maximum.value, max(1, preferred.value))

    def _bind(self):
        signatures = {
            "clGetPlatformIDs": (STATUS, [U, C.POINTER(P), C.POINTER(U)]),
            "clGetDeviceIDs": (STATUS, [P, L, U, C.POINTER(P), C.POINTER(U)]),
            "clGetDeviceInfo": (STATUS, [P, U, Z, P, C.POINTER(Z)]),
            "clCreateContext": (
                P,
                [C.POINTER(C.c_ssize_t), U, C.POINTER(P), P, P, C.POINTER(STATUS)],
            ),
            "clCreateCommandQueue": (P, [P, P, L, C.POINTER(STATUS)]),
            "clCreateProgramWithSource": (
                P,
                [P, U, C.POINTER(C.c_char_p), C.POINTER(Z), C.POINTER(STATUS)],
            ),
            "clBuildProgram": (STATUS, [P, U, C.POINTER(P), C.c_char_p, P, P]),
            "clGetProgramBuildInfo": (STATUS, [P, P, U, Z, P, C.POINTER(Z)]),
            "clCreateKernel": (P, [P, C.c_char_p, C.POINTER(STATUS)]),
            "clGetKernelWorkGroupInfo": (STATUS, [P, P, U, Z, P, C.POINTER(Z)]),
            "clCreateBuffer": (P, [P, L, Z, P, C.POINTER(STATUS)]),
            "clSetKernelArg": (STATUS, [P, U, Z, P]),
            "clEnqueueNDRangeKernel": (
                STATUS,
                [
                    P,
                    P,
                    U,
                    C.POINTER(Z),
                    C.POINTER(Z),
                    C.POINTER(Z),
                    U,
                    C.POINTER(P),
                    C.POINTER(P),
                ],
            ),
            "clEnqueueReadBuffer": (
                STATUS,
                [P, P, U, Z, Z, P, U, C.POINTER(P), C.POINTER(P)],
            ),
            "clEnqueueWriteBuffer": (
                STATUS,
                [P, P, U, Z, Z, P, U, C.POINTER(P), C.POINTER(P)],
            ),
            "clFinish": (STATUS, [P]),
        }
        for name in (
            "clReleaseContext",
            "clReleaseCommandQueue",
            "clReleaseProgram",
            "clReleaseKernel",
            "clReleaseMemObject",
        ):
            signatures[name] = (STATUS, [P])
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, name)
            function.restype = result
            function.argtypes = args

    @staticmethod
    def check(status):
        if status:
            raise RuntimeError(f"OpenCL API exit status {status}")

    @staticmethod
    def info(function, obj, field):
        size = Z()
        OpenCLFilter.check(function(obj, field, 0, None, C.byref(size)))
        value = C.create_string_buffer(size.value)
        OpenCLFilter.check(function(obj, field, len(value), value, None))
        return value.value.decode("utf-8", errors="replace")

    def _buffer(self, flags, size, data=None):
        error = STATUS()
        buffer = self.lib.clCreateBuffer(
            self.context, flags, size,
            None if data is None else data.ctypes.data, C.byref(error),
        )
        self.check(error.value)
        self.owned.append(("clReleaseMemObject", buffer))
        return buffer

    def _inputs(self, prefix, cipher):
        values = (prefix.tobytes(), cipher.tobytes())
        if not self._input_buffers:
            for data in (prefix, cipher):
                self._input_buffers.append(self._buffer(4 | 32, data.nbytes, data))
        elif values != self._input_values:
            for buffer, data in zip(self._input_buffers, (prefix, cipher)):
                self.check(self.lib.clEnqueueWriteBuffer(
                    self.queue, buffer, 1, 0, data.nbytes, data.ctypes.data,
                    0, None, None,
                ))
        # Only RAM is used to detect unchanged inputs; nothing is serialized.
        self._input_values = values

    def scan(self, prefix, cipher, start, count, max_output):
        if not self.owned:
            raise RuntimeError("OpenCL filter is closed")
        if len(prefix) != 16 or len(cipher) < 128:
            raise ValueError("OpenCL requires 16 prefix bytes and 128 ciphertext bytes")
        if not (0 <= start < 2**32 and 0 < count <= min(1 << 23, 2**32 - start)):
            raise ValueError("Invalid bounded OpenCL range")
        if not 0 < max_output < 2**32:
            raise ValueError("Invalid OpenCL output bound")
        prefix = np.ascontiguousarray(prefix, dtype=np.uint8)
        cipher = np.ascontiguousarray(cipher[:128], dtype=np.uint8)
        if prefix.ndim != 1 or cipher.ndim != 1:
            raise ValueError("OpenCL input arrays must be one-dimensional")
        self._inputs(prefix, cipher)
        output = np.empty(count, dtype=np.uint8)
        if count > self._output_capacity:
            replacement = self._buffer(2, count)
            if self._output_buffer is not None:
                self.check(self.lib.clReleaseMemObject(self._output_buffer))
                self.owned.remove(("clReleaseMemObject", self._output_buffer))
            self._output_buffer = replacement
            self._output_capacity = count
        arguments = [
            P(self._input_buffers[0]), P(self._input_buffers[1]),
            U(start), U(count), U(max_output), P(self._output_buffer),
        ]
        for index, arg in enumerate(arguments):
            self.check(self.lib.clSetKernelArg(
                self.kernel, index, C.sizeof(arg), C.byref(arg)
            ))
        local = Z(self.local_size)
        global_size = Z((count + local.value - 1) // local.value * local.value)
        self.check(self.lib.clEnqueueNDRangeKernel(
            self.queue, self.kernel, 1, None, C.byref(global_size), C.byref(local),
            0, None, None,
        ))
        self.check(self.lib.clEnqueueReadBuffer(
            self.queue, self._output_buffer, 1, 0, output.nbytes,
            output.ctypes.data, 0, None, None,
        ))
        return output

    def close(self):
        for function, obj in reversed(self.owned):
            getattr(self.lib, function)(obj)
        self.owned.clear()
        self._input_buffers.clear()
        self._input_values = None
        self._output_buffer = None
        self._output_capacity = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
