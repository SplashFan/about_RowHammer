#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import mmap
import os
import platform
import random
from dataclasses import dataclass
from pathlib import Path

ROW_SIZE = 8192  # Условный размер строки
VICTIM_PATTERN = 0xAA
AGGRESSOR_PATTERN = 0x55
FLIP_STEP = 25_000  # Параметр расчётной модели


@dataclass(frozen=True)
class Scenario:
    name: str
    pattern: str
    simulated_activations: int
    model_refresh: bool = False


SCENARIOS = [
    Scenario("control", "double", 0),
    Scenario("single_60000", "single", 60_000),
    Scenario("double_25000", "double", 25_000),
    Scenario("double_60000", "double", 60_000),
    Scenario("double_100000", "double", 100_000),
    Scenario("double_150000", "double", 150_000),
    Scenario("double_150000_refresh", "double", 150_000, True),
]


def sha256(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def modeled_bit_flips(scenario: Scenario) -> int:
    """Условная пороговая модель; это не результат измерений DRAM."""
    threshold = 90_000 if scenario.pattern == "single" else 50_000
    if scenario.model_refresh:
        # Идеализированная защита: предполагается, что обновление строки исключает ошибку.
        return 0
    excess = scenario.simulated_activations - threshold
    return min(10, (excess // FLIP_STEP) + 1) if excess >= 0 else 0


def run_scenario(scenario: Scenario):
    # Выделяем область виртуальной памяти Linux с помощью анонимного mmap.
    # Соседние смещения в этой области не означают физически соседние строки DRAM.
    with mmap.mmap(-1, ROW_SIZE * 3, access=mmap.ACCESS_WRITE) as mem:
        mem[0:ROW_SIZE] = bytes([AGGRESSOR_PATTERN]) * ROW_SIZE
        mem[ROW_SIZE:ROW_SIZE * 2] = bytes([VICTIM_PATTERN]) * ROW_SIZE
        mem[ROW_SIZE * 2:ROW_SIZE * 3] = bytes([AGGRESSOR_PATTERN]) * ROW_SIZE

        before = mem[ROW_SIZE:ROW_SIZE * 2]
        before_hash = sha256(before)

        # Читаем условные области воздействия по обе стороны от проверяемой области.
        # Эти чтения процессора не эквивалентны активациям строк DRAM;
        # число активаций здесь — входной параметр расчёта, а не показание счётчика.
        _ = mem[0] ^ mem[ROW_SIZE * 2]
        if scenario.pattern == "double":
            _ ^= mem[ROW_SIZE - 1] ^ mem[ROW_SIZE * 3 - 1]

        number_of_faults = modeled_bit_flips(scenario)
        rng = random.Random(f"rowhammer-lab-v1:{scenario.name}")
        byte_offsets = rng.sample(range(ROW_SIZE), number_of_faults)
        examples = []
        for idx, offset in enumerate(sorted(byte_offsets)):
            pos = ROW_SIZE + offset
            old_value = mem[pos]
            bit = (idx * 3 + 1) % 8
            mem[pos] = old_value ^ (1 << bit)  # Программное внесение битовой ошибки
            examples.append((offset, bit, old_value, mem[pos]))

        after = mem[ROW_SIZE:ROW_SIZE * 2]
        xor_sum = sum((a ^ b).bit_count() for a, b in zip(before, after))
        byte_errors = sum(a != b for a, b in zip(before, after))
        return {
            "scenario": scenario.name,
            "pattern": scenario.pattern,
            "simulated_activations": scenario.simulated_activations,
            "modeled_refresh": scenario.model_refresh,
            "bit_flips": xor_sum,
            "changed_bytes": byte_errors,
            "integrity_ok": before_hash == sha256(after),
            "sha256_before": before_hash,
            "sha256_after": sha256(after),
            "examples": examples,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="results.csv", help="Output CSV path")
    args = parser.parse_args()

    print("ROW HAMMER: EDUCATIONAL FAULT-INJECTION MODEL")
    print("DISCLAIMER: simulated flips; NOT physical DRAM Rowhammer!")
    print("Linux kernel :", platform.release())
    print("Platform     :", platform.platform())
    print("Page size    :", os.sysconf("SC_PAGE_SIZE"), "bytes")
    print("Model        : [aggressor][victim][aggressor]")
    print("Memory       : 3 x 8192 B (anonymous mmap; virtual addresses)")
    print("Victim init  : 0xAA, 65536 checked bits")
    print("Assumptions  : threshold=50k (double) / 90k (single)")
    print("Protection   : idealized refresh blocks synthetic faults")
    print("-" * 77)
    print(f"{'SCENARIO':27} {'ACTIVATIONS':>11} {'FLIPS':>7} {'SHA256 MATCH':>13}")
    print("-" * 77)

    results = [run_scenario(s) for s in SCENARIOS]
    for r in results:
        print(f"{r['scenario']:27} {r['simulated_activations']:>11,} "
              f"{r['bit_flips']:>7} {str(r['integrity_ok']).upper():>13}")

    print("-" * 77)
    demo = next(r for r in results if r["scenario"] == "double_100000")
    print("Example synthetic bit flips (double_100000):")
    for addr, bit, old, new in demo["examples"]:
        print(f"  victim offset=0x{addr:04X}, bit={bit}, 0x{old:02X} -> 0x{new:02X}")
    print("SHA256 before:", demo["sha256_before"][:32] + "...")
    print("SHA256 after :", demo["sha256_after"][:32] + "...")

    fields = ["scenario", "pattern", "simulated_activations", "modeled_refresh",
              "bit_flips", "changed_bytes", "integrity_ok", "sha256_before", "sha256_after"]
    path = Path(args.csv)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({key: r[key] for key in fields})
    print("CSV saved    :", path)
    print("CONCLUSION   : model confirms integrity loss only after explicit fault injection")


if __name__ == "__main__":
    main()
