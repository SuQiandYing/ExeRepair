"""Identical synthetic workload for baseline, optimized and rollback trees."""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import statistics
import struct
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1 << 23)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.package_root))
    from exerepair.adapters.aplib import AplibCompressor
    from exerepair.adapters.component_recovery import _primitives, verify_filter
    from exerepair.adapters.opencl_filter import L, Z, OpenCLFilter

    np, md5, rc4, cpu = _primitives()
    compressor = AplibCompressor()
    fixture = b"".join(hashlib.sha256(struct.pack("<I", i)).digest() for i in range(256))
    packed = compressor(fixture)
    prefix = np.arange(16, dtype=np.uint8)
    cipher = rc4(np.frombuffer(packed, dtype=np.uint8),
                 np.concatenate((prefix, md5(0x12345678))))[:128]
    initialization_start = time.perf_counter()
    with OpenCLFilter() as engine:
        initialization = time.perf_counter() - initialization_start
        verification = verify_filter(engine, compressor)
        oracle_cases = 0
        for case, (start, maximum) in enumerate([
            (0x12345000, len(fixture)), (0xFFFFF000, len(fixture)),
            (0, 16), (0x80000000, 1 << 24),
        ]):
            test_prefix = prefix if case < 2 else np.roll(prefix, case)
            test_cipher = cipher if case < 2 else np.roll(cipher, case)
            expected = cpu(test_prefix, test_cipher, start, 4096, maximum)
            assert np.array_equal(
                engine.scan(test_prefix, test_cipher, start, 4096, maximum), expected
            ), f"independent CPU/GPU mismatch: synthetic case {case}"
            oracle_cases += 4096
        expected = cpu(prefix, cipher, 0x12345000, 4096, len(fixture))
        for _ in range(2):
            assert np.array_equal(
                engine.scan(prefix, cipher, 0x12345000, 4096, len(fixture)), expected
            )
        engine.scan(prefix, cipher, 0x12000000, 65536, len(fixture))
        times, hashes = [], []
        for _ in range(args.rounds):
            start = time.perf_counter()
            flags = engine.scan(prefix, cipher, 0x12000000, args.count, len(fixture))
            times.append(time.perf_counter() - start)
            assert flags[0x12345678 - 0x12000000] == 1
            hashes.append(hashlib.sha256(flags.tobytes()).hexdigest())
        assert len(set(hashes)) == 1
        private = L()
        engine.check(engine.lib.clGetKernelWorkGroupInfo(
            engine.kernel, engine.device, 0x11B4, C.sizeof(private),
            C.byref(private), None,
        ))
        maximum = Z()
        engine.check(engine.lib.clGetKernelWorkGroupInfo(
            engine.kernel, engine.device, 0x11B0, C.sizeof(maximum),
            C.byref(maximum), None,
        ))
        result = {
            "format": "exerepair.speed-benchmark.v1",
            "scope": "synthetic only; no real activation value is used",
            "device": engine.device_name,
            "local_size": engine.local_size,
            "kernel_private_bytes": private.value,
            "maximum_work_group_size": maximum.value,
            "initialization_seconds": initialization,
            "synthetic_verification": verification,
            "additional_cpu_oracle_candidates": oracle_cases,
            "count_per_round": args.count,
            "rounds": args.rounds,
            "seconds": times,
            "median_seconds": statistics.median(times),
            "candidates_per_second": args.count / statistics.median(times),
            "flags_sha256": hashes[0],
            "accepted_candidates": int(np.count_nonzero(flags)),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    assert json.loads(args.output.read_text(encoding="utf-8")) == result
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
