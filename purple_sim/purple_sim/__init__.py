"""
purple_sim — an autonomous Red vs Blue (Purple Team) network simulation.

A self-contained research sandbox where an offensive (Red) agent and a
defensive (Blue) agent take turns on an abstract, MITRE ATT&CK-mapped
network. The environment keeps *ground truth* hidden and gives Blue only a
noisy, delayed telemetry feed — so detection means something.

Three agent families share one environment:
  - heuristic : deterministic baselines (no dependencies, always available)
  - llm       : prompted Red/Blue; mock mode works offline, or call the Claude API
  - rl        : Gym-style wrapper so RL agents can train on the same env

Nothing here touches a real network. Vulnerabilities are abstract flags and
"CVE"/technique labels are just strings used for scoring and vocabulary.
"""

__version__ = "0.2.0"
