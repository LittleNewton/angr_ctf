import angr
import claripy
import sys


def find_path(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())


bin_path = './07_angr_symbolic_file.elf'
proj = angr.Project(bin_path)

start_addr = 0x080493e6
init_state = proj.factory.blank_state(addr=start_addr)

file_size = 0x40
password = claripy.BVS('password', file_size * 8)
file_name = 'KBECVEJF.txt'
sim_file = angr.SimFile(file_name, password, size=file_size)

init_state.fs.insert(file_name, sim_file)

simgr = proj.factory.simulation_manager(init_state)
simgr.explore(find=find_path, avoid=avoid_path)

if simgr.found:
    solution_state = simgr.found[0]
    solution = solution_state.solver.eval(password, cast_to=bytes)
    print(solution)
else:
    raise Exception("Could not find the solution")
