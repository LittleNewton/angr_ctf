# angr.sim_file stub — SimFile

from __future__ import annotations

from typing import Any, Optional, Union

import claripy


class SimFile:
    """Symbolic file abstraction for use with state.fs."""

    def __init__(
        self,
        name: str,
        content: Optional[Union[claripy.ast.Base, bytes, str]] = None,
        *,
        size: Optional[Union[int, claripy.ast.Base]] = None,
        seekable: bool = True,
        writable: bool = True,
        ident: Optional[str] = None,
        **kwargs: Any,
    ) -> None: ...

    # Attributes
    name: str
    size: Any          # claripy.ast.Base or int
    content: Any
