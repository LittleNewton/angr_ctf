# angr.factory stub — AngrObjectFactory

from __future__ import annotations

from typing import Any, Dict, Optional, Set, Union

import claripy
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager


class AngrObjectFactory:
    """Produces SimState and SimulationManager instances."""

    # ------------------------------------------------------------------ #
    #  State constructors                                                  #
    # ------------------------------------------------------------------ #
    def entry_state(
        self,
        *,
        args: Any = None,
        env: Any = None,
        stdin: Any = None,
        add_options: Optional[Set[str]] = None,
        remove_options: Optional[Set[str]] = None,
        **kwargs: Any,
    ) -> SimState: ...

    def blank_state(
        self,
        *,
        addr: Optional[int] = None,
        add_options: Optional[Set[str]] = None,
        remove_options: Optional[Set[str]] = None,
        **kwargs: Any,
    ) -> SimState: ...

    def call_state(
        self,
        addr: int,
        *args: Any,
        add_options: Optional[Set[str]] = None,
        remove_options: Optional[Set[str]] = None,
        **kwargs: Any,
    ) -> SimState: ...

    # ------------------------------------------------------------------ #
    #  SimulationManager constructors                                     #
    # ------------------------------------------------------------------ #
    def simgr(
        self,
        thing: Optional[Union[SimState, Any]] = None,
        *,
        veritesting: bool = False,
        **kwargs: Any,
    ) -> SimulationManager: ...

    def simulation_manager(
        self,
        thing: Optional[Union[SimState, Any]] = None,
        *,
        veritesting: bool = False,
        **kwargs: Any,
    ) -> SimulationManager: ...
