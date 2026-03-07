# angr._sim_procedures stub — SIM_PROCEDURES dict
# Usage: angr.SIM_PROCEDURES['libc']['scanf']()

from __future__ import annotations

from typing import Any, Dict, Type
from angr.sim_procedure import SimProcedure

# SIM_PROCEDURES is a two-level dict:  library_name -> func_name -> SimProcedure class
SIM_PROCEDURES: Dict[str, Dict[str, Type[SimProcedure]]]
