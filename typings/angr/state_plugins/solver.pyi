# angr.state_plugins.solver stub — SimSolver (state.solver)

from __future__ import annotations

from typing import Any, List, Literal, Optional, Type, Union, overload

import claripy


class SimSolver:
    """Symbolic solver plugin attached to SimState as `state.solver`."""

    # ------------------------------------------------------------------ #
    #  Evaluation                                                          #
    # ------------------------------------------------------------------ #
    @overload
    def eval(
        self,
        e: claripy.ast.Base,
        *,
        cast_to: Type[bytes],
        n: int = 1,
        extra_constraints: Any = ...,
    ) -> bytes: ...

    @overload
    def eval(
        self,
        e: claripy.ast.Base,
        *,
        cast_to: Type[int],
        n: int = 1,
        extra_constraints: Any = ...,
    ) -> int: ...

    @overload
    def eval(
        self,
        e: claripy.ast.Base,
        n: int = 1,
        *,
        extra_constraints: Any = ...,
    ) -> int: ...

    def eval(self, e: Any, n: int = 1, **kwargs: Any) -> Any: ...

    def eval_one(
        self,
        e: claripy.ast.Base,
        *,
        extra_constraints: Any = ...,
        **kwargs: Any,
    ) -> int: ...

    def eval_upto(
        self,
        e: claripy.ast.Base,
        n: int,
        *,
        cast_to: Optional[type] = None,
        **kwargs: Any,
    ) -> List[Any]: ...

    def min(self, e: claripy.ast.Base, **kwargs: Any) -> int: ...
    def max(self, e: claripy.ast.Base, **kwargs: Any) -> int: ...

    # ------------------------------------------------------------------ #
    #  Constraints                                                         #
    # ------------------------------------------------------------------ #
    def add(self, *constraints: claripy.ast.Base) -> None: ...
    def satisfiable(self, extra_constraints: Any = ...) -> bool: ...

    # ------------------------------------------------------------------ #
    #  Symbolic variable creation (常见补充)                              #
    # ------------------------------------------------------------------ #
    def BVS(
        self,
        name: str,
        size: int,
        *,
        min: Optional[int] = None,
        max: Optional[int] = None,
        stride: Optional[int] = None,
        uninitialized: bool = False,
        explicit_name: bool = False,
        **kwargs: Any,
    ) -> claripy.ast.BV: ...

    def BVV(
        self,
        value: Union[int, bytes],
        size: Optional[int] = None,
        **kwargs: Any,
    ) -> claripy.ast.BV: ...
