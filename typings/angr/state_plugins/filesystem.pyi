# angr.state_plugins.filesystem stub — SimFilesystem (state.fs)

from __future__ import annotations

from typing import Any, Optional

from angr.sim_file import SimFile


class SimFilesystem:
    """Filesystem plugin attached to SimState as `state.fs`."""

    def insert(self, name: str, simfile: SimFile) -> None:
        """Mount *simfile* at path *name* in the simulated filesystem."""
        ...

    def get(self, name: str) -> Optional[SimFile]: ...
    def delete(self, name: str) -> None: ...
