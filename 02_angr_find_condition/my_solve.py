import angr
import sys


def find_path(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


bin_path = "./02_angr_find_condition.elf"
proj = angr.Project(bin_path)
init_state = proj.factory.entry_state()
simgr = proj.factory.simgr(init_state)

simgr.explore(find=find_path, avoid=avoid_path)

if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
    print("No solution found.")
