import angr
import claripy


bin_path = './06_angr_symbolic_dynamic_memory.elf'

project = angr.Project(bin_path)

after_scanf_addr = 0x080492e0
init_state = project.factory.blank_state(addr=after_scanf_addr)


buf0_addr = 0x0a9f0538
buf1_addr = 0x0a9f053c

fake_chunk0_addr = 0x1145140
fake_chunk1_addr = 0x1145200

# ---------------
# 为什么需要 fake chunk?
#
# 因为我们的 init_state 是 blank_state, 之前的初始化工作都没做，只是一个虚假的状态。
#
# 尽管如此，但是我们的init_state是scanf之后的第一条指令。
# 所以这个时候正常程序的scanf已经完成。但是由于我们是blank state,
# 所以这里的 scanf 和之前的 malloc 都没跑过，所以等价于不存在。
# ---------------


init_state.memory.store(buf0_addr, fake_chunk0_addr, endness=project.arch.memory_endness)
init_state.memory.store(buf1_addr, fake_chunk1_addr, endness=project.arch.memory_endness)

# create symbolic variables for the content of the fake chunks
pasword0 = claripy.BVS('password0', 64)
pasword1 = claripy.BVS('password1', 64)
init_state.memory.store(fake_chunk0_addr, pasword0)
init_state.memory.store(fake_chunk1_addr, pasword1)

simgr = project.factory.simulation_manager(init_state)
simgr.explore(find=0x080493ae, avoid=0x0804939c)

if simgr.found:
    found_state = simgr.found[0]
    password0 = found_state.solver.eval(pasword0, cast_to=bytes)
    password1 = found_state.solver.eval(pasword1, cast_to=bytes)
    print(f'password0: {password0}')
    print(f'password1: {password1}')
else:
    print('No solution found.')
