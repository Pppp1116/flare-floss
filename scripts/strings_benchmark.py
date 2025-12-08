#!/usr/bin/env python3
"""
Lightweight benchmark and regression helper for FLOSS string extraction.

Examples:
    python scripts/strings_benchmark.py /path/to/binary --iterations 5 --save-output baseline.json
    python scripts/strings_benchmark.py /path/to/binary --compare baseline.json
"""

from __future__ import annotations

import argparse
import json
import tracemalloc
import time
from pathlib import Path
from typing import Iterable, List, Tuple

from floss.utils import extract_strings


def serialize_strings(strings: Iterable) -> List[dict]:
    return [
        {"string": s.string, "offset": s.offset, "encoding": getattr(s.encoding, "name", str(s.encoding))}
        for s in strings
    ]


def run_extraction(buffer: bytes, min_length: int) -> Tuple[List, float, int]:
    tracemalloc.start()
    start = time.perf_counter()
    strings = list(extract_strings(buffer, min_length))
    duration = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return strings, duration, peak


def compare_against_baseline(new_strings: List[dict], baseline_path: Path) -> dict:
    baseline = json.loads(baseline_path.read_text())
    baseline_strings = baseline.get("strings", [])

    new_set = {(s["string"], s["encoding"], s["offset"]) for s in new_strings}
    baseline_set = {(s["string"], s["encoding"], s["offset"]) for s in baseline_strings}

    missing = baseline_set - new_set
    added = new_set - baseline_set

    return {
        "baseline_count": len(baseline_strings),
        "new_count": len(new_strings),
        "missing": sorted(missing),
        "added": sorted(added),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Target binary to run string extraction on")
    parser.add_argument("--min-length", type=int, default=4, help="Minimum string length")
    parser.add_argument("--iterations", type=int, default=3, help="Number of timed iterations to average")
    parser.add_argument("--save-output", type=Path, help="Optional path to persist extracted strings as JSON")
    parser.add_argument(
        "--compare", type=Path, help="Baseline JSON created by --save-output to run a regression diff against"
    )
    args = parser.parse_args()

    data = args.binary.read_bytes()
    timings: List[float] = []
    peaks: List[int] = []
    last_strings: List = []

    for _ in range(args.iterations):
        strings, duration, peak = run_extraction(data, args.min_length)
        last_strings = strings
        timings.append(duration)
        peaks.append(peak)

    serialized = serialize_strings(last_strings)
    best = min(timings)
    avg = sum(timings) / len(timings)
    throughput_best = len(data) / best if best else 0
    throughput_avg = len(data) / avg if avg else 0

    print(f"Iterations: {args.iterations}\nCount: {len(serialized)}")
    print(f"Best: {best:.4f}s ({throughput_best:.2f} bytes/s)")
    print(f"Avg: {avg:.4f}s ({throughput_avg:.2f} bytes/s)")
    print(f"Peak RSS (tracemalloc): {max(peaks) / (1024 * 1024):.2f} MiB")

    if args.save_output:
        payload = {
            "file": str(args.binary.resolve()),
            "min_length": args.min_length,
            "strings": serialized,
        }
        args.save_output.write_text(json.dumps(payload, indent=2))
        print(f"Saved extraction output to {args.save_output}")

    if args.compare:
        diff = compare_against_baseline(serialized, args.compare)
        print("Baseline comparison:")
        print(f"  baseline strings: {diff['baseline_count']}")
        print(f"  new strings:      {diff['new_count']}")
        print(f"  missing:          {len(diff['missing'])}")
        print(f"  added:            {len(diff['added'])}")
        if diff["missing"] or diff["added"]:
            print("  missing items:")
            for item in diff["missing"]:
                print(f"    {item}")
            print("  added items:")
            for item in diff["added"]:
                print(f"    {item}")


if __name__ == "__main__":
    main()
