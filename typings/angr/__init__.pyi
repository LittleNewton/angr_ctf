# angr stub — covers API actually used in angr_ctf lessons 00-14.
# "常见补充" marks entries added for completeness beyond observed usage.

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Union, overload
import collections.abc

from angr.project import Project
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from angr.sim_procedure import SimProcedure
from angr.sim_file import SimFile
from angr import options
from angr._sim_procedures import SIM_PROCEDURES

__all__ = [
    "Project",
    "SimState",
    "SimulationManager",
    "SimProcedure",
    "SimFile",
    "options",
    "SIM_PROCEDURES",
]
