import angr
import sys
import claripy


bin_path = './05_angr_symbolic_memory.elf'

proj = angr.Project(bin_path)
start_addr = 0x08049289
start_state = proj.factory.blank_state(addr=start_addr)

password_0 = claripy.BVS('password_0', 64)
password_1 = claripy.BVS('password_1', 64)
password_2 = claripy.BVS('password_2', 64)
password_3 = claripy.BVS('password_3', 64)

start_state.memory.store(0x82f48a0, password_0)
start_state.memory.store(0x82f48a8, password_1)
start_state.memory.store(0x82f48b0, password_2)
start_state.memory.store(0x82f48b8, password_3)

simgr = proj.factory.simulation_manager(start_state)

simgr.explore(find=0x080492fd, avoid=0x080491e6)

if simgr.found:
    found_state = simgr.found[0]
    password_0_value = found_state.solver.eval(password_0, cast_to=bytes)
    password_1_value = found_state.solver.eval(password_1, cast_to=bytes)
    password_2_value = found_state.solver.eval(password_2, cast_to=bytes)
    password_3_value = found_state.solver.eval(password_3, cast_to=bytes)

    print('password_0:', password_0_value)
    print('password_1:', password_1_value)
    print('password_2:', password_2_value)
    print('password_3:', password_3_value)
else:
    print("No solution found.")
