#!/usr/bin/env python3
"""Aggregate billed-token + cost metrics from a Harbor run for the compression
A/B. Scans a jobs dir for Harbor trajectory.json files and sums final_metrics
across all trials.

Usage:  aggregate_metrics.py <jobs_dir> [label]
        aggregate_metrics.py compare <jobs_dir_off> <jobs_dir_on>

For Claude trajectories, cache write/read fields are reported separately. For
Codex trajectories, Harbor currently reports aggregate cached input tokens as
total_cached_tokens, which this script treats as cache_read for display.
"""
import json
import sys
from pathlib import Path

# Sonnet 4.6 pricing, USD per million tokens.
IN, OUT = 3.00, 15.00
CACHE_WRITE_5M = IN * 1.25   # 3.75
CACHE_READ = IN * 0.10       # 0.30


def collect(jobs_dir: str) -> dict:
    root = Path(jobs_dir)
    agg = {"trials": 0, "prompt": 0, "completion": 0, "cache_read": 0,
           "cache_creation": 0, "reported_cost": 0.0, "has_reported_cost": False}
    for tj in root.rglob("trajectory.json"):
        try:
            fm = json.loads(tj.read_text()).get("final_metrics") or {}
        except (OSError, json.JSONDecodeError):
            continue
        agg["trials"] += 1
        agg["prompt"] += fm.get("total_prompt_tokens") or 0
        agg["completion"] += fm.get("total_completion_tokens") or 0
        agg["cache_read"] += (
            fm.get("total_cache_read_input_tokens")
            or fm.get("total_cached_tokens")
            or 0
        )
        agg["cache_creation"] += fm.get("total_cache_creation_input_tokens") or 0
        if fm.get("total_cost_usd") is not None:
            agg["reported_cost"] += fm["total_cost_usd"]
            agg["has_reported_cost"] = True
    # total_prompt_tokens already includes cache read + creation; back out fresh input.
    agg["fresh_input"] = max(0, agg["prompt"] - agg["cache_read"] - agg["cache_creation"])
    agg["calc_cost"] = (
        agg["fresh_input"] * IN
        + agg["cache_creation"] * CACHE_WRITE_5M
        + agg["cache_read"] * CACHE_READ
        + agg["completion"] * OUT
    ) / 1e6
    return agg


def show(label: str, a: dict):
    cache_total = a["cache_read"] + a["cache_creation"]
    hit = (100 * a["cache_read"] / cache_total) if cache_total else 0.0
    print(f"  [{label}] trials={a['trials']}")
    print(f"    prompt(total) : {a['prompt']:>12,}  (fresh={a['fresh_input']:,}, "
          f"cache_read={a['cache_read']:,}, cache_write={a['cache_creation']:,})")
    print(f"    completion    : {a['completion']:>12,}")
    print(f"    cache hit rate: {hit:>11.1f}%")
    print(f"    cost (Sonnet calc): ${a['calc_cost']:>11.4f}")
    if a["has_reported_cost"]:
        print(f"    cost (agent reported): ${a['reported_cost']:.4f}")
    else:
        print("    cost (agent reported): n/a")


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "compare":
        off, on = collect(sys.argv[2]), collect(sys.argv[3])
        print("=== compression OFF vs ON ===")
        show("off", off); show("on", on)
        d = on["calc_cost"] - off["calc_cost"]
        pct = (100 * d / off["calc_cost"]) if off["calc_cost"] else 0.0
        print(f"\n  delta cost (on - off): ${d:+.4f}  ({pct:+.1f}%)")
        return
    jobs_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    label = sys.argv[2] if len(sys.argv) > 2 else "run"
    a = collect(jobs_dir)
    if a["trials"] == 0:
        print(f"  (no trajectory.json found under {jobs_dir})")
        return
    show(label, a)


if __name__ == "__main__":
    main()
