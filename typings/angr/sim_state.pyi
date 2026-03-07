# angr.sim_state stub — SimState

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional, Union

import claripy
from angr.state_plugins.solver import SimSolver
from angr.state_plugins.posix import SimSystemPosix
from angr.state_plugins.filesystem import SimFilesystem
from angr.state_plugins.memory import SimMemory
from angr.state_plugins.registers import SimRegNamespace


class SimState:
    """Represents a single program state during symbolic execution."""

    # ------------------------------------------------------------------ #
    #  Core plugins                                                        #
    # ------------------------------------------------------------------ #
    regs: SimRegNamespace
    memory: SimMemory
    solver: SimSolver
    posix: SimSystemPosix
    fs: SimFilesystem
    arch: Any           # archinfo.Arch
    globals: Dict[str, Any]
    history: Any        # SimStateHistory — typed as Any
    callstack: Any

    # ------------------------------------------------------------------ #
    #  Stack helpers (常见补充)                                            #
    # ------------------------------------------------------------------ #
    def stack_push(self, thing: Union[claripy.ast.Base, int]) -> None: ...
    def stack_pop(self) -> claripy.ast.Base: ...

    # ------------------------------------------------------------------ #
    #  Constraint helpers                                                  #
    # ------------------------------------------------------------------ #
    def add_constraints(self, *args: claripy.ast.Base) -> None: ...

    # ------------------------------------------------------------------ #
    #  Misc                                                                #
    # ------------------------------------------------------------------ #
    def copy(self) -> SimState: ...
    def merge(self, *others: SimState, **kwargs: Any) -> tuple[SimState, Any, Any]: ...

    # Allow arbitrary attribute access for less-common plugins (returns Any)
    def __getattr__(self, name: str) -> Any: ...
