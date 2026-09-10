#!/usr/bin/env python3
"""V2.5 coverage analysis: paired per-seed comparisons and within-strategy
connect-rate correlations (RQ1/RQ2 statistics).

PRIMARY (RQ1): per-seed paired marginal parse-reachable regions, S vs B1_1x.
  marginal(arm,s) = | (arm_union \\ seed) ∩ parse_reachable |   (asymmetric set diff)
  - paired Wilcoxon signed-rank (Pratt zeros) two-sided + one-sided directional
  - effect: matched-pairs rank-biserial r + Hodges-Lehmann median Δ + cluster BCa CI
    (resample whole seeds), reported regardless of direction
  - TOST equivalence at ±MCID; top-down decision matrix (directional / ≈ / inconclusive)
SECONDARY: full_loader marginal; B0 context; set-diff (files S opens that B1 doesn't);
  RQ2 within-strategy Spearman (connect_rate vs marginal).
Also verifies startup ⊆ seed (so the marginal is startup-free by construction).

MCID: from a noise-floor rerun dataset when present; otherwise COV_MCID (placeholder,
clearly labeled). Bitsets are read LSB-first (bitorder='little') to match coverage_extract.

Usage: coverage_analyze.py [EXPERIMENT_DIR] [UNIVERSE_JSON]
"""
import json
import os
import sys
import numpy as np

EXP = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "COV_OUT", "/home/ssw/bugbounty/data/coverage/experiment")
UNIV = sys.argv[2] if len(sys.argv) > 2 else os.environ.get(
    "COV_UNIVERSE", "/home/ssw/bugbounty/data/coverage/universe.json")
MCID = float(os.environ.get("COV_MCID", "3"))   # placeholder until noise floor measured
ALPHA = 0.05
PRIMARY_ARM = "S"
COMPARATOR = "B1_1x"


def load_universe():
    u = json.load(open(UNIV))
    n = u["region_count"]
    parse_mask = np.zeros(n, dtype=bool)
    parse_mask[np.array(u["parse_ids"], dtype=np.int64)] = True
    return n, parse_mask, u


def load_bits(path, n):
    raw = np.frombuffer(open(path, "rb").read(), dtype=np.uint8)
    if raw.size == 0:
        return np.zeros(n, dtype=bool)
    return np.unpackbits(raw, count=n, bitorder="little").astype(bool)


# Per-region-group classification. RQ1 ("reaches deeper loader code") is
# only interpretable per layer: parser-error BREADTH vs post-parse DEPTH.
GROUP_ORDER = ["parser", "checker_shapeinf", "graph", "optimizer", "cpu_ep", "framework_session"]


def group_of(path):
    if "/_deps/onnx-build/onnx/" in path or "/protobuf-src/src/google/protobuf/" in path:
        return "parser"
    if "/_deps/onnx-src/onnx/" in path:
        return "checker_shapeinf"
    if "/onnxruntime/core/graph/" in path:
        return "graph"
    if "/onnxruntime/core/optimizer/" in path:
        return "optimizer"
    if "/providers/" in path or "/contrib_ops/" in path:
        return "cpu_ep"
    return "framework_session"  # framework/session/flatbuffers/common/platform


def build_group_masks(universe, n):
    files = universe["files"]
    masks = {g: np.zeros(n, dtype=bool) for g in GROUP_ORDER}
    for i, k in enumerate(universe["keys"]):
        masks[group_of(files[k[0]])][i] = True
    return masks


def gather(n, parse_mask):
    man = json.load(open(os.path.join(EXP, "manifest.json")))
    rows = []           # per (seed, arm)
    s_marg, b_marg = {}, {}  # region OR-accumulators for set-diff (parse group)
    marg_bits = {}      # (sid, arm) -> full marginal bool array (for per-group decomposition)
    for s in man["seeds"]:
        sid = s["seed_id"]
        seed = load_bits(os.path.join(EXP, sid, "seed.bin"), n)
        for arm in s["arms"]:
            u = load_bits(os.path.join(EXP, sid, arm, "union.bin"), n)
            marg = u & ~seed
            marg_bits[(sid, arm)] = marg
            mp = int((marg & parse_mask).sum())
            mf = int(marg.sum())
            recs = json.load(open(os.path.join(EXP, sid, arm, "records.json")))["records"]
            sess = [r.get("session_ok") for r in recs]
            connect = float(np.mean([1 if x else 0 for x in sess])) if sess else 0.0
            rows.append({"seed": sid, "arm": arm, "marg_parse": mp, "marg_full": mf,
                         "connect_rate": connect, "seed_cov": int(seed.sum())})
            if arm == PRIMARY_ARM:
                s_marg[sid] = (marg & parse_mask)
            if arm == COMPARATOR:
                b_marg[sid] = (marg & parse_mask)
    return man, rows, s_marg, b_marg, marg_bits


def hodges_lehmann(d):
    d = np.asarray(d, float)
    n = len(d)
    w = [(d[i] + d[j]) / 2 for i in range(n) for j in range(i, n)]
    return float(np.median(w)) if w else 0.0


def rank_biserial(d):
    from scipy.stats import rankdata
    d = np.asarray(d, float)
    d = d[d != 0]
    if d.size == 0:
        return 0.0
    r = rankdata(np.abs(d))
    wp, wn = r[d > 0].sum(), r[d < 0].sum()
    return float((wp - wn) / (wp + wn)) if (wp + wn) > 0 else 0.0


def rq1(rows):
    from scipy.stats import wilcoxon, bootstrap
    by = {}
    for r in rows:
        by.setdefault(r["seed"], {})[r["arm"]] = r
    seeds = [s for s in by if PRIMARY_ARM in by[s] and COMPARATOR in by[s]]
    seeds.sort()
    sv = np.array([by[s][PRIMARY_ARM]["marg_parse"] for s in seeds], float)
    bv = np.array([by[s][COMPARATOR]["marg_parse"] for s in seeds], float)
    diffs = sv - bv
    out = {"n": len(seeds), "seeds": seeds,
           "S": sv.tolist(), "B1": bv.tolist(), "diffs": diffs.tolist(),
           "median_S": float(np.median(sv)), "median_B1": float(np.median(bv)),
           "HL_median_delta": hodges_lehmann(diffs),
           "rank_biserial_r": rank_biserial(diffs), "MCID": MCID}

    def wil(x, alt):
        try:
            return float(wilcoxon(x, zero_method="pratt", alternative=alt).pvalue)
        except ValueError:
            return float("nan")
    out["p_two_sided"] = wil(diffs, "two-sided")
    out["p_greater"] = wil(diffs, "greater")   # S > B1
    out["p_less"] = wil(diffs, "less")         # S < B1
    # TOST equivalence within ±MCID
    out["p_tost_upper"] = wil(diffs - MCID, "less")     # median < +MCID
    out["p_tost_lower"] = wil(diffs + MCID, "greater")  # median > -MCID
    out["tost_equivalent"] = (out["p_tost_upper"] < ALPHA and out["p_tost_lower"] < ALPHA)
    # cluster BCa CI on median(diffs) (resample seeds)
    try:
        res = bootstrap((diffs,), np.median, n_resamples=10000, method="BCa",
                        random_state=12345)
        out["ci_median_low"] = float(res.confidence_interval.low)
        out["ci_median_high"] = float(res.confidence_interval.high)
    except Exception as e:
        out["ci_median_low"] = out["ci_median_high"] = None
        out["ci_error"] = str(e)
    # decision matrix (top-down precedence)
    hl = out["HL_median_delta"]
    if out["p_two_sided"] < ALPHA and abs(hl) >= MCID:
        out["decision"] = f"DIRECTIONAL: {'S>B1' if hl > 0 else 'S<B1'}"
    elif out["tost_equivalent"]:
        out["decision"] = "EQUIVALENT (S≈B1 within ±MCID)"
    else:
        out["decision"] = "INCONCLUSIVE"
    return out


def rq2(rows):
    from scipy.stats import spearmanr
    res = {}
    for arm in {r["arm"] for r in rows}:
        a = [(r["connect_rate"], r["marg_parse"]) for r in rows if r["arm"] == arm]
        if len(a) >= 3 and len({x for x, _ in a}) >= 2:
            x = [p[0] for p in a]; y = [p[1] for p in a]
            rho, p = spearmanr(x, y)
            res[arm] = {"n": len(a), "rho": float(rho), "p": float(p)}
        else:
            res[arm] = {"n": len(a), "rho": None, "note": "connect_rate constant or n<3 (needs intensity sweep)"}
    return res


def setdiff(s_marg, b_marg, universe, topk=12):
    n = universe["region_count"]
    s_any = np.zeros(n, bool); b_any = np.zeros(n, bool)
    for v in s_marg.values():
        s_any |= v
    for v in b_marg.values():
        b_any |= v
    s_only = s_any & ~b_any
    b_only = b_any & ~s_any
    files = universe["files"]; keys = universe["keys"]

    def by_file(mask):
        from collections import Counter
        c = Counter()
        for i in np.nonzero(mask)[0]:
            c[files[keys[i][0]]] += 1
        return c
    return {"s_only_total": int(s_only.sum()), "b1_only_total": int(b_only.sum()),
            "s_only_top": by_file(s_only).most_common(topk),
            "b1_only_top": by_file(b_only).most_common(topk)}


def startup_check(n):
    man = json.load(open(os.path.join(EXP, "manifest.json")))
    seedbits = [load_bits(os.path.join(EXP, s["seed_id"], "seed.bin"), n) for s in man["seeds"]]
    if not seedbits:
        return {}
    startup = seedbits[0].copy()
    for b in seedbits[1:]:
        startup &= b
    subset_ok = all(bool((startup & ~b).sum() == 0) for b in seedbits)
    return {"startup_size": int(startup.sum()), "startup_subset_of_all_seeds": subset_ok}


def short(p):
    return os.path.basename(p)


def group_decomp(marg_bits, group_masks, seeds, a, b):
    out = []
    for g in GROUP_ORDER:
        mask = group_masks[g]
        at = sum(int((marg_bits[(s, a)] & mask).sum()) for s in seeds if (s, a) in marg_bits)
        bt = sum(int((marg_bits[(s, b)] & mask).sum()) for s in seeds if (s, b) in marg_bits)
        wins_a = sum(1 for s in seeds if (s, a) in marg_bits and (s, b) in marg_bits
                     and int((marg_bits[(s, a)] & mask).sum()) > int((marg_bits[(s, b)] & mask).sum()))
        out.append((g, at, bt, wins_a))
    return out


def main():
    n, parse_mask, universe = load_universe()
    man, rows, s_marg, b_marg, marg_bits = gather(n, parse_mask)
    group_masks = build_group_masks(universe, n)
    print(f"=== dataset: {len(man['seeds'])} seeds, universe={n} regions "
          f"(parse_reachable={int(parse_mask.sum())}) ===")
    print(f"{'seed':<26}{'arm':<7}{'marg_parse':>11}{'marg_full':>11}{'connect':>9}")
    for r in rows:
        print(f"{r['seed']:<26}{r['arm']:<7}{r['marg_parse']:>11}{r['marg_full']:>11}{r['connect_rate']:>9.3f}")

    r1 = rq1(rows)
    print(f"\n=== RQ1 PRIMARY: {PRIMARY_ARM} vs {COMPARATOR}, marginal parse-reachable regions (n={r1['n']} seeds) ===")
    print(f"  per-seed S:    {r1['S']}")
    print(f"  per-seed B1:   {r1['B1']}")
    print(f"  diffs (S-B1):  {r1['diffs']}")
    print(f"  median S={r1['median_S']:.1f}  median B1={r1['median_B1']:.1f}  HL median Δ={r1['HL_median_delta']:.2f}")
    print(f"  Wilcoxon two-sided p={r1['p_two_sided']:.4f}  (S>B1 p={r1['p_greater']:.4f}, S<B1 p={r1['p_less']:.4f})")
    print(f"  rank-biserial r={r1['rank_biserial_r']:.3f}")
    ci = (f"[{r1['ci_median_low']:.2f}, {r1['ci_median_high']:.2f}]"
          if r1.get('ci_median_low') is not None else f"(BCa failed: {r1.get('ci_error','')})")
    print(f"  cluster BCa 95% CI on median Δ: {ci}")
    print(f"  TOST equivalence within ±{MCID} (placeholder MCID): {r1['tost_equivalent']} "
          f"(upper p={r1['p_tost_upper']:.4f}, lower p={r1['p_tost_lower']:.4f})")
    print(f"  >>> DECISION (placeholder MCID={MCID}): {r1['decision']}")
    print("  NOTE: MCID is a placeholder until the noise-floor rerun sets it; smoke n is tiny.")

    gd = group_decomp(marg_bits, group_masks, r1["seeds"], PRIMARY_ARM, COMPARATOR)
    print(f"\n=== per-region-group decomposition (marginal regions summed over {r1['n']} seeds; {PRIMARY_ARM} vs {COMPARATOR}) ===")
    print(f"  {'group':<20}{PRIMARY_ARM+'_total':>10}{COMPARATOR+'_total':>12}{'seeds '+PRIMARY_ARM+'>'+COMPARATOR:>16}")
    for g, at, bt, wa in gd:
        lead = PRIMARY_ARM if at > bt else (COMPARATOR if bt > at else "tie")
        print(f"  {g:<20}{at:>10}{bt:>12}{wa:>13}/{r1['n']}   <- {lead}")
    print("  (parser=protobuf decode BREADTH; graph/checker_shapeinf=post-parse DEPTH. RQ1 interpreted per layer.)")

    sd = setdiff(s_marg, b_marg, universe)
    print(f"\n=== set-diff (parse-reachable regions opened by ONE arm only, aggregated over seeds) ===")
    print(f"  S-only regions:  {sd['s_only_total']}   B1-only regions: {sd['b1_only_total']}")
    print("  top files S opens that B1 does not:")
    for f, c in sd["s_only_top"][:8]:
        print(f"    {c:>5}  {short(f)}")
    print("  top files B1 opens that S does not:")
    for f, c in sd["b1_only_top"][:8]:
        print(f"    {c:>5}  {short(f)}")

    r2 = rq2(rows)
    print(f"\n=== RQ2: within-strategy Spearman (connect_rate vs marginal, cross-seed) ===")
    for arm, v in sorted(r2.items()):
        if v.get("rho") is None:
            print(f"  {arm}: {v.get('note')}")
        else:
            print(f"  {arm}: rho={v['rho']:.3f} p={v['p']:.4f} (n={v['n']})")
    print("  NOTE: the prereg's confirmatory RQ2 uses the intensity sweep (≥4 levels) for within-strategy variation; this cross-seed cut is a first look.")

    sc = startup_check(n)
    print(f"\n=== startup check ===")
    print(f"  startup (∩ all seeds) = {sc.get('startup_size')} regions; startup ⊆ every seed: {sc.get('startup_subset_of_all_seeds')}")
    print("  (marginal = arm \\ seed, so startup ⊆ seed ⇒ marginal is startup-free by construction)")


if __name__ == "__main__":
    main()
