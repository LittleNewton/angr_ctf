# angr.sim_manager stub — SimulationManager

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Union

import claripy
from angr.sim_state import SimState


# A predicate can be a plain callable or an address (int)
_FindSpec = Union[int, Callable[[SimState], bool], List[int]]
_AvoidSpec = Union[int, Callable[[SimState], bool], List[int]]


class SimulationManager:
    """Manages a set of symbolic execution states (stashes)."""

    # ------------------------------------------------------------------ #
    #  Standard stashes                                                    #
    # ------------------------------------------------------------------ #
    active: List[SimState]
    found: List[SimState]
    avoided: List[SimState]
    deadended: List[SimState]
    errored: List[Any]

    # ------------------------------------------------------------------ #
    #  Exploration                                                         #
    # ------------------------------------------------------------------ #
    def explore(
        self,
        *,
        find: Optional[_FindSpec] = None,
        avoid: Optional[_AvoidSpec] = None,
        find_stash: str = "found",
        avoid_stash: str = "avoided",
        n: Optional[int] = None,
        step_func: Optional[Callable[["SimulationManager"], "SimulationManager"]] = None,
        **kwargs: Any,
    ) -> "SimulationManager": ...

    # ------------------------------------------------------------------ #
    #  Stepping                                                            #
    # ------------------------------------------------------------------ #
    def step(
        self,
        stash: str = "active",
        n: Optional[int] = None,
        **kwargs: Any,
    ) -> "SimulationManager": ...

    def run(
        self,
        stash: str = "active",
        n: Optional[int] = None,
        until: Optional[Callable[["SimulationManager"], bool]] = None,
        **kwargs: Any,
    ) -> "SimulationManager": ...

    # ------------------------------------------------------------------ #
    #  Stash management (常见补充)                                        #
    # ------------------------------------------------------------------ #
    def move(
        self,
        from_stash: str,
        to_stash: str,
        filter_func: Optional[Callable[[SimState], bool]] = None,
    ) -> "SimulationManager": ...

    def stash(
        self,
        filter_func: Optional[Callable[[SimState], bool]] = None,
        from_stash: str = "active",
        to_stash: str = "stashed",
    ) -> "SimulationManager": ...

    # Allow `simgr['stash_name']` access
    def __getitem__(self, key: str) -> List[SimState]: ...
    def __setitem__(self, key: str, value: List[SimState]) -> None: ...
