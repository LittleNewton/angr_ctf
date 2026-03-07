# angr.state_plugins.registers stub — SimRegNamespace (state.regs)

from __future__ import annotations

from typing import Any, Union

import claripy


class SimRegNamespace:
    """Register access namespace: state.regs.eax, state.regs.rbp, etc."""

    # x86 registers observed in the repo
    eax: claripy.ast.BV
    ebx: claripy.ast.BV
    ecx: claripy.ast.BV
    edx: claripy.ast.BV
    esi: claripy.ast.BV
    edi: claripy.ast.BV
    esp: claripy.ast.BV
    ebp: claripy.ast.BV
    eip: claripy.ast.BV

    # 常见补充 — x86-64
    rax: claripy.ast.BV
    rbx: claripy.ast.BV
    rcx: claripy.ast.BV
    rdx: claripy.ast.BV
    rsi: claripy.ast.BV
    rdi: claripy.ast.BV
    rsp: claripy.ast.BV
    rbp: claripy.ast.BV
    rip: claripy.ast.BV

    # Dynamic access for any register not listed above
    def __getattr__(self, name: str) -> claripy.ast.BV: ...
    def __setattr__(self, name: str, value: Union[claripy.ast.BV, int]) -> None: ...
