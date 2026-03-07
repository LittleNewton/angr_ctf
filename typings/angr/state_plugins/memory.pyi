# angr.state_plugins.memory stub — SimMemory (state.memory)

from __future__ import annotations

from typing import Any, Optional, Union

import claripy


class SimMemory:
    """Memory plugin attached to SimState as `state.memory`."""

    def store(
        self,
        addr: Union[int, claripy.ast.Base],
        data: Union[int, bytes, claripy.ast.Base],
        size: Optional[Union[int, claripy.ast.Base]] = None,
        *,
        condition: Optional[claripy.ast.Base] = None,
        add_constraints: Optional[bool] = None,
        endness: Optional[str] = None,
        inspect: bool = True,
        disable_actions: bool = False,
        **kwargs: Any,
    ) -> None: ...

    def load(
        self,
        addr: Union[int, claripy.ast.Base],
        size: Optional[Union[int, claripy.ast.Base]] = None,
        *,
        condition: Optional[claripy.ast.Base] = None,
        fallback: Optional[claripy.ast.Base] = None,
        add_constraints: Optional[bool] = None,
        endness: Optional[str] = None,
        inspect: bool = True,
        disable_actions: bool = False,
        **kwargs: Any,
    ) -> claripy.ast.BV: ...
