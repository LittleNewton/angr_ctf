# claripy.ast.bv stub — BV (bitvector) AST node

from __future__ import annotations

from claripy.ast.base import Base


class BV(Base):
    """Bitvector AST node — the most common claripy type."""

    length: int  # number of bits

    # Concat / Extract helpers (常见补充)
    def zero_extend(self, n: int) -> BV: ...
    def sign_extend(self, n: int) -> BV: ...
    def reversed(self) -> BV: ...
    def chop(self, bits: int = 8) -> list[BV]: ...

    # Slice syntax: bv[high:low]
    def __getitem__(self, index: slice) -> BV: ...
