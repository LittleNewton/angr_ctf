# angr.sim_procedure stub — SimProcedure base class

from __future__ import annotations

from typing import Any, Optional

import claripy
from angr.sim_state import SimState


class SimProcedure:
    """Base class for hooking / replacing binary functions."""

    # Set on instantiation by the angr engine
    state: SimState
    project: Any       # angr.Project — avoid circular import
    successors: Any
    arguments: Any
    ret_to: Any
    ret_expr: Any
    cc: Any            # calling convention

    def __init__(self, **kwargs: Any) -> None: ...

    # Override this in subclasses:
    def run(self, *args: Any, **kwargs: Any) -> Any: ...

    # Helpers available inside run():
    def inline_call(
        self,
        procedure: "type[SimProcedure]",
        *args: Any,
        **kwargs: Any,
    ) -> "SimProcedure": ...

    def ret(self, expr: Optional[Any] = None) -> None: ...
    def jump(self, to: int) -> None: ...
    def exit(self, exit_code: Any) -> None: ...
    def call(self, addr: int, args: Any, continue_at: str, **kwargs: Any) -> None: ...

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...
