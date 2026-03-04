import angr
import sys


bin_path = './03_angr_symbolic_registers.elf'
proj = angr.Project(bin_path)

target_good = 0x080494da
avoid_try = 0x080494b4


entry_state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(entry_state)
simgr.explore(find=target_good, avoid=avoid_try)
if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
    print(solution_state.posix.dumps(sys.stdout.fileno()).decode())
else:
    print("No solution found.")
