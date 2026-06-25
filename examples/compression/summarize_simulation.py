#!/usr/bin/env python3
"""Summarize the gateway's `ctxedit simulate` log lines into a verdict on the two
questions, without ever rewriting a request or running a live ON run:

  #1 Would compression fire, and how many tokens would it save?
  #2 Would it bust the prompt cache, and how many cached tokens are at risk?

Usage:  summarize_simulation.py <gateway_log>

CACHE MODEL (important): compression is a deterministic, content-only function, so
fragment B always compresses to the same B'. The client resends uncompressed B
every turn; we re-emit B' identically; the upstream's cached COMPRESSED prefix is
byte-stable turn-over-turn => steady-state cache HIT, no ongoing busting.

Therefore:
  * `saved_tokens` is REAL and RECURRING — every turn the prefix is that much
    smaller, billed at cache-read price once cached. (Summed across a session's
    turns it counts the recurring per-turn savings.)
  * `cached_tokens_at_risk` / `busted_breakpoints` measure divergence from the
    *uncompressed* baseline — i.e. the ONE-TIME transition cost when a fragment
    first enters the cached region. It does NOT recur, so we report the per-request
    MAX (representative one-time hit), never the sum.
This only holds while compression stays deterministic (see EMPTY_QUERY note in
dispatch.rs). Token counts are a cl100k estimate.
"""
import re
import sys

# Sonnet 4.6 pricing, USD per million tokens.
IN = 3.00
CACHE_WRITE = IN * 1.25   # 3.75 — one-time write of the compressed prefix
CACHE_READ = IN * 0.10    # 0.30 — recurring per-turn price of the (smaller) cached prefix

FIELDS = ("messages", "eligible", "fired", "saved_bytes", "saved_tokens",
          "busted_breakpoints", "cached_tokens_at_risk")


def main():
    log = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin"
    rows = []
    try:
        for line in open(log):
            if "ctxedit simulate" not in line:
                continue
            kv = dict(re.findall(r"(\w+)=(-?\d+)", line))
            rows.append({f: int(kv.get(f, 0)) for f in FIELDS})
    except OSError as e:
        print(f"  (cannot read {log}: {e})")
        return
    if not rows:
        print("  (no 'ctxedit simulate' lines — was the gateway run with simulate:true?)")
        return

    reqs = len(rows)
    fired_reqs = sum(1 for r in rows if r["fired"] > 0)
    elig = sum(r["eligible"] for r in rows)
    fired = sum(r["fired"] for r in rows)
    # Largest request ~= the full accumulated context near end of session; its
    # saved_tokens is the per-turn steady-state prefix reduction.
    peak = max(rows, key=lambda r: r["saved_tokens"])
    saved_peak = peak["saved_tokens"]
    max_at_risk = max(r["cached_tokens_at_risk"] for r in rows)
    any_busted = sum(1 for r in rows if r["busted_breakpoints"] > 0)

    print(f"  requests analyzed : {reqs}")
    print(f"  fires in          : {fired_reqs}/{reqs} requests "
          f"({100*fired_reqs/reqs:.0f}%); {fired}/{elig} tool_results")
    print(f"  #1 FIRE  (recurring): peak per-turn prefix reduction ~{saved_peak:,} tokens")
    print(f"     => recurring savings ~${saved_peak*CACHE_READ/1e6:.4f}/turn "
          f"(smaller cached prefix at $0.30/M)")
    print(f"  #2 CACHE (one-time) : {any_busted}/{reqs} requests bust a breakpoint; "
          f"max one-time at-risk ~{max_at_risk:,} tokens")
    print(f"     => one-time write ~${max_at_risk*CACHE_WRITE/1e6:.4f} "
          f"(amortizes to ~0 over the session; deterministic ⇒ no recurring bust)")
    if max_at_risk == 0:
        print("     verdict: FREE — all changes land in the fresh tail (busted=0).")
    else:
        print("     verdict: net-positive in steady state — recurring savings vs a "
              "single transition write. (Do NOT sum at-risk across turns.)")


if __name__ == "__main__":
    main()
