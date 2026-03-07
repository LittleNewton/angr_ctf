# angr.state_plugins.posix stub — SimSystemPosix (state.posix)

from __future__ import annotations

from typing import Any, Union

import claripy


class SimSystemPosix:
    """POSIX plugin attached to SimState as `state.posix`."""

    def dumps(self, fd: int) -> bytes:
        """Return the concrete bytes written to file-descriptor *fd*.

        Common usage::

            solution = state.posix.dumps(sys.stdout.fileno())  # fd=1
        """
        ...

    def get_fd(self, fd: int) -> Any: ...

    stdin: Any
    stdout: Any
    stderr: Any
