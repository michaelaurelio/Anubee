"""Unit tests for the loop-folding internals in trace_store."""

from trace_store import _find_runs, _select, _fold, _collect_loops


def test_find_runs_simple_period_two():
    toks = ["a", "b", "a", "b", "a", "b"]
    runs = _find_runs(toks, max_period=32, min_reps=3)
    assert (2, 0, 3) in runs


def test_find_runs_period_one():
    runs = _find_runs(["a", "a", "a", "a"], max_period=32, min_reps=3)
    assert (1, 0, 4) in runs


def test_find_runs_below_min_reps():
    # only two repeats of "a b" -> not a run at min_reps=3
    runs = _find_runs(["a", "b", "a", "b"], max_period=32, min_reps=3)
    assert all(k < 3 for _, _, k in runs) or runs == []


def _nodes(seq):
    return [{"tok": s, "name": s, "ids": [i], "body": None}
            for i, s in enumerate(seq)]


def test_fold_collapses_consecutive_loop():
    seq = ["x"] + ["a", "b", "c"] * 4 + ["y"]
    folded = _fold(_nodes(seq), max_period=32, min_reps=3)
    loops = {}
    for nd in folded:
        _collect_loops(nd, loops)
    assert len(loops) == 1
    body, info = next(iter(loops.items()))
    assert info["body"] == ["a", "b", "c"]
    assert info["iterations_total"] == 4
    assert info["period"] == 3


def test_select_no_overlap():
    runs = [(1, 0, 4), (2, 0, 2)]      # overlapping at offset 0
    chosen = _select(list(runs))
    # both can't be chosen (they overlap); the selector keeps a non-overlapping set
    occ = [(i, i + p * k) for p, i, k in chosen]
    for a in range(len(occ)):
        for b in range(a + 1, len(occ)):
            lo1, hi1 = occ[a]; lo2, hi2 = occ[b]
            assert hi1 <= lo2 or hi2 <= lo1
