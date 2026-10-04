"""Small statistics helpers so results are reported with uncertainty, not as
single point estimates. Pure stdlib.

- Win rates are proportions: use a Wilson score interval (well-behaved for
  small n and extreme rates, unlike the normal approximation).
- Means (scores, coverage) get a normal/t-style CI from the sample stdev.
- `compare_proportions` says whether two win rates differ significantly (its
  difference CI excludes zero), so "A beats B" is a claim, not noise.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Sequence, Tuple

Z95 = 1.959963984540054  # two-sided 95%


def wilson_interval(successes: int, n: int, z: float = Z95) -> Tuple[float, float]:
    """95% CI for a proportion (0..1) by the Wilson score method."""
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def mean_ci(values: Sequence[float], z: float = Z95) -> Tuple[float, float, float]:
    """(mean, lo, hi) 95% CI for a sample mean. Degenerate -> zero-width."""
    n = len(values)
    if n == 0:
        return (0.0, 0.0, 0.0)
    m = statistics.mean(values)
    if n < 2:
        return (m, m, m)
    se = statistics.stdev(values) / math.sqrt(n)
    return (m, m - z * se, m + z * se)


@dataclass
class Comparison:
    diff: float            # p1 - p2 (proportions, 0..1)
    lo: float
    hi: float

    @property
    def significant(self) -> bool:
        """True when the 95% CI for the difference excludes zero."""
        return self.lo > 0 or self.hi < 0


def compare_proportions(s1: int, n1: int, s2: int, n2: int, z: float = Z95) -> Comparison:
    """95% CI for p1 - p2 (normal approximation to the difference)."""
    if n1 <= 0 or n2 <= 0:
        return Comparison(0.0, 0.0, 0.0)
    p1, p2 = s1 / n1, s2 / n2
    se = math.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)
    d = p1 - p2
    return Comparison(d, d - z * se, d + z * se)


def pct_ci(successes: int, n: int) -> str:
    """'63% [57, 69]' — a proportion with its 95% CI, as percentages."""
    lo, hi = wilson_interval(successes, n)
    return f"{100 * successes / n:.0f}% [{100 * lo:.0f}, {100 * hi:.0f}]" if n else "n/a"


def mean_pm(values: Sequence[float]) -> str:
    """'29.0 ±3.1' — a mean with its 95% half-width."""
    m, lo, hi = mean_ci(values)
    return f"{m:.1f} ±{(hi - lo) / 2:.1f}"
