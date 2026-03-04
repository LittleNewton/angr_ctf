import angr
import claripy
import sys

# TODO: 可能是有点问题，veritesting 不起作用。

bin_path = './12_angr_veritesting.elf'
proj = angr.Project(bin_path, auto_load_libs=False)

# Hook exit() so angr doesn't get stuck when complex_function rejects out-of-range chars
proj.hook_symbol('exit', angr.SIM_PROCEDURES['libc']['exit']())

init_state = proj.factory.entry_state(
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
simgr = proj.factory.simgr(init_state, veritesting=True)
simgr.explore(find=0x080492c2, avoid=0x080492d4)

if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('Could not find the solution!')
