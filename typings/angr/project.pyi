# angr.project stub

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Set, Union

import claripy
from angr.factory import AngrObjectFactory
from angr.sim_procedure import SimProcedure


class Project:
    """angr top-level project object."""

    # Attributes
    entry: int
    arch: Any          # archinfo.Arch — typed as Any to avoid archinfo dependency
    loader: Any        # cle.Loader
    factory: AngrObjectFactory
    filename: str

    # ------------------------------------------------------------------ #
    #  Construction                                                        #
    # ------------------------------------------------------------------ #
    def __init__(
        self,
        thing: str,
        *,
        auto_load_libs: bool = True,
        load_options: Optional[Dict[str, Any]] = None,
        use_sim_procedures: bool = True,
        exclude_sim_procedures_func: Optional[Callable[..., bool]] = None,
        ignore_functions: Optional[Any] = None,
        support_selfmodifying_code: bool = False,
        **kwargs: Any,
    ) -> None: ...

    # ------------------------------------------------------------------ #
    #  Hooking                                                             #
    # ------------------------------------------------------------------ #
    def hook(
        self,
        addr: int,
        hook: Optional[Union[SimProcedure, Callable[..., Any]]] = None,
        length: int = 0,
        kwargs: Optional[Dict[str, Any]] = None,
        replace: bool = False,
    ) -> Any:
        """Hook *addr*.

        When used as a decorator (no *hook* argument supplied) returns a
        decorator that registers the wrapped function as a hook.
        """
        ...

    def hook_symbol(
        self,
        symbol_name: str,
        simproc: SimProcedure,
        kwargs: Optional[Dict[str, Any]] = None,
        replace: Optional[bool] = None,
    ) -> None: ...

    def is_hooked(self, addr: int) -> bool: ...
    def unhook(self, addr: int) -> None: ...
