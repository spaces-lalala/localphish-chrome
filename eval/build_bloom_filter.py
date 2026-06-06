"""Offline bloom-filter builder for the on-device 165/TWCERT TW phish-URL feed.

Reads `eval/datasets/tw_scam_domains.jsonl` (produced by
`fetch_tw_scam_domains.py`), constructs a bloom filter sized for the current
row count + 10x growth headroom, and writes:

  extension/src/data/tw-scam-bloom.json
      Metadata-only sidecar (m, k, n, hash family, version, source notes).
      Inline base64 of the bit array goes in `bits_b64` so we don't have to
      ship a separate binary file inside the @crxjs Vite bundle.

The bloom filter contract is fixed and intentionally simple — the TS decoder
re-implements it byte-for-byte without dependencies:
  - hashing: double FNV-1a (32-bit, two independent seeds A=2166136261, B=16777619+seed_offset)
  - k hashes derived as h1 + i*h2  (mod m) for i in [0, k)
  - bit array packed MSB-first into base64

This is the bloom-filter "two-hash trick" (Kirsch & Mitzenmacher, 2006):
two real hashes generate k synthetic hashes with no asymptotic FPR penalty.
We never need a real crypto hash here — only uniform output across the bit
array. FNV-1a is sufficient and trivially portable.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import sys
from pathlib import Path

from rich.console import Console


FNV_OFFSET_A = 0x811C9DC5
FNV_OFFSET_B = 0xCBF29CE4   # different constant — independent hash family
FNV_PRIME = 0x01000193


def fnv1a(s: str, seed: int) -> int:
    """32-bit FNV-1a. Input is encoded UTF-8; output is uint32."""
    h = seed & 0xFFFFFFFF
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h


def optimal_m_k(n: int, target_fpr: float) -> tuple[int, int]:
    """Standard bloom-filter sizing.

    m = -n * ln(p) / (ln 2)^2
    k = (m / n) * ln 2
    """
    if n <= 0:
        # Empty filter: give it a small fixed footprint, still useful as a
        # signal-spec placeholder until fetch runs.
        return (256, 7)
    m = math.ceil(-n * math.log(target_fpr) / (math.log(2) ** 2))
    # Round up to the next multiple of 8 so it packs cleanly into bytes.
    m = ((m + 7) // 8) * 8
    k = max(1, math.ceil((m / n) * math.log(2)))
    return (m, k)


def bit_positions(domain: str, m: int, k: int) -> list[int]:
    h1 = fnv1a(domain, FNV_OFFSET_A)
    h2 = fnv1a(domain, FNV_OFFSET_B) | 1  # force odd so step is coprime with m for many m
    return [((h1 + i * h2) & 0xFFFFFFFF) % m for i in range(k)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "datasets/tw_scam_domains.jsonl")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data/tw-scam-bloom.json")
    parser.add_argument("--target-fpr", type=float, default=0.001,
                        help="Target false-positive rate at the planned final size")
    parser.add_argument("--growth", type=float, default=10.0,
                        help="Size the filter for N*growth domains so we can absorb feed updates without rebuild")
    args = parser.parse_args()
    console = Console()

    # ---- Load domains -----------------------------------------------------
    domains: list[str] = []
    if args.input.exists():
        with args.input.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                d = row.get("domain")
                if isinstance(d, str) and d:
                    domains.append(d)
    else:
        console.print(f"[yellow]Note:[/yellow] {args.input} not found — building EMPTY bloom filter")
        console.print(
            "[yellow]Hint:[/yellow] run `uv run python fetch_tw_scam_domains.py` first "
            "to populate the feed. An empty filter is a valid placeholder that "
            "never matches; the extension ships with it and we refresh via "
            "chrome.alarms once an authenticated network is available."
        )

    n = len(domains)
    planned = max(1, int(round(n * args.growth)))
    m, k = optimal_m_k(planned, args.target_fpr)

    console.print(
        f"[cyan]Bloom params[/cyan]: n={n} actual, "
        f"planned={planned} (growth={args.growth}x), "
        f"target FPR={args.target_fpr}, m={m} bits ({m // 8} bytes), k={k}"
    )

    # ---- Encode -----------------------------------------------------------
    bits = bytearray((m + 7) // 8)
    for d in domains:
        for pos in bit_positions(d, m, k):
            bits[pos // 8] |= (1 << (7 - (pos % 8)))  # MSB-first inside byte

    b64 = base64.b64encode(bytes(bits)).decode("ascii")

    # ---- Self-check (everything we inserted should now hit) ---------------
    misses = 0
    for d in domains:
        for pos in bit_positions(d, m, k):
            if not (bits[pos // 8] & (1 << (7 - (pos % 8)))):
                misses += 1
                break
    if misses:
        console.print(f"[red]Self-check FAILED[/red]: {misses}/{n} inserted domains miss")
        return 1
    if n:
        console.print(f"[green]Self-check OK[/green]: all {n} inserted domains hit")

    # ---- Empirical FPR (1000 random non-members) --------------------------
    import secrets
    members = set(domains)
    fp = 0
    trials = 1000
    for _ in range(trials):
        # random unrelated domain string
        token = secrets.token_hex(8) + ".test.invalid"
        if token in members:
            continue
        hit = all(bits[pos // 8] & (1 << (7 - (pos % 8))) for pos in bit_positions(token, m, k))
        if hit:
            fp += 1
    emp_fpr = fp / trials
    console.print(f"  empirical FPR (1000 random non-members): {emp_fpr:.4f}")

    # ---- Write metadata + blob --------------------------------------------
    out = {
        "_comment": (
            "165反詐騙專線 TW phish-URL bloom filter (data.gov.tw dataset 176455, "
            "政府資料開放授權條款 第1版 ≡ CC BY 4.0). Rebuild via "
            "eval/build_bloom_filter.py. Probed at Stage 1; bit-set = treat host "
            "as DANGEROUS short-circuit. Empty filter = inert."
        ),
        "_source": "https://data.gov.tw/dataset/176455",
        "_attribution": "165反詐騙諮詢專線_遭停止解析涉詐網站 (內政部警政署)",
        "_license": "政府資料開放授權條款 第1版",
        "version": 1,
        "hash_family": "double-fnv1a-32",
        "fnv_offset_a": FNV_OFFSET_A,
        "fnv_offset_b": FNV_OFFSET_B,
        "fnv_prime": FNV_PRIME,
        "m_bits": m,
        "k_hashes": k,
        "n_inserted": n,
        "planned_capacity": planned,
        "target_fpr": args.target_fpr,
        "empirical_fpr": round(emp_fpr, 4),
        "bits_b64": b64,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"[green]wrote[/green] {args.out}  ({len(b64) // 1024} KB base64)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
