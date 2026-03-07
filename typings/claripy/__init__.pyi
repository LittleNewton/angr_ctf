# claripy stub — covers API used in angr_ctf lessons 00-14.

from __future__ import annotations

from typing import Any, Optional, Union

from claripy.ast.base import Base, Bool
from claripy.ast.bv import BV

__all__ = [
    "Base",
    "Bool",
    "BV",
    "BVS",
    "BVV",
    "BoolS",
    "BoolV",
    "If",
    "And",
    "Or",
    "Not",
    "Concat",
    "Extract",
    "ZeroExt",
    "SignExt",
    "RotateLeft",
    "RotateRight",
    "LShR",
    "ULT",
    "ULE",
    "UGT",
    "UGE",
    "SLT",
    "SLE",
    "SGT",
    "SGE",
    "true",
    "false",
    "backends",
    "backend_manager",
]

# ------------------------------------------------------------------ #
#  Symbolic variable constructors                                      #
# ------------------------------------------------------------------ #

def BVS(
    name: str,
    size: int,
    *,
    min: Optional[int] = None,
    max: Optional[int] = None,
    stride: Optional[int] = None,
    uninitialized: bool = False,
    explicit_name: bool = False,
    **kwargs: Any,
) -> BV:
    """Create a symbolic bitvector of *size* bits."""
    ...

def BVV(
    value: Union[int, bytes, str],
    size: Optional[int] = None,
    **kwargs: Any,
) -> BV:
    """Create a concrete bitvector."""
    ...

def BoolS(name: str, **kwargs: Any) -> Bool: ...
def BoolV(value: bool, **kwargs: Any) -> Bool: ...

# ------------------------------------------------------------------ #
#  Conditional / logical                                               #
# ------------------------------------------------------------------ #

def If(
    cond: Union[Bool, Base],
    true_val: Union[BV, Base, int],
    false_val: Union[BV, Base, int],
) -> BV:
    """Symbolic if-then-else."""
    ...

def And(*args: Union[Bool, Base]) -> Bool: ...
def Or(*args: Union[Bool, Base]) -> Bool: ...
def Not(arg: Union[Bool, Base]) -> Bool: ...

# ------------------------------------------------------------------ #
#  Bitvector operations (常见补充)                                    #
# ------------------------------------------------------------------ #

def Concat(*args: Union[BV, Base]) -> BV: ...

def Extract(high: int, low: int, bv: Union[BV, Base]) -> BV: ...

def ZeroExt(n: int, bv: Union[BV, Base]) -> BV: ...
def SignExt(n: int, bv: Union[BV, Base]) -> BV: ...

def RotateLeft(bv: Union[BV, Base], n: Union[BV, Base, int]) -> BV: ...
def RotateRight(bv: Union[BV, Base], n: Union[BV, Base, int]) -> BV: ...
def LShR(bv: Union[BV, Base], n: Union[BV, Base, int]) -> BV: ...

# Unsigned / signed comparisons returning Bool
def ULT(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def ULE(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def UGT(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def UGE(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def SLT(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def SLE(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def SGT(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...
def SGE(a: Union[BV, Base], b: Union[BV, Base, int]) -> Bool: ...

# ------------------------------------------------------------------ #
#  Constants                                                           #
# ------------------------------------------------------------------ #

true: Bool
false: Bool

# ------------------------------------------------------------------ #
#  Backend / solver (常见补充)                                        #
# ------------------------------------------------------------------ #

backends: Any
backend_manager: Any

def Solver(**kwargs: Any) -> Any: ...
