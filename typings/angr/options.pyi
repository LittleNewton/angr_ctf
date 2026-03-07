# angr.options stub — symbolic execution options
# Only options actually used in the repo are given precise names;
# the rest fall through __getattr__ -> str.

from __future__ import annotations

# Used in 12_angr_veritesting / entry_state(add_options={...})
SYMBOL_FILL_UNCONSTRAINED_MEMORY: str
SYMBOL_FILL_UNCONSTRAINED_REGISTERS: str

# 常见补充 — frequently referenced options
LAZY_SOLVES: str
UNDER_CONSTRAINED_SYMEXEC: str
ZERO_FILL_UNCONSTRAINED_MEMORY: str
ZERO_FILL_UNCONSTRAINED_REGISTERS: str
SIMPLIFY_MEMORY_READS: str
SIMPLIFY_MEMORY_WRITES: str

def __getattr__(name: str) -> str: ...
