import angr
import claripy
import sys


bin_path = './09_angr_hooks.elf'
proj = angr.Project(bin_path)

buff_addr = 0x0804c02c
buff_size = 0x10
passwd_addr = 0x0804c040
compared_str = b'XFQUUEQFKBECVEJF'

init_state = proj.factory.blank_state(addr=0x080492ed)

buffer = claripy.BVS('buffer', buff_size * 8)
init_state.memory.store(buff_addr, buffer)

password_size = 0x10

# Store the concrete value of the password at the static address
init_state.memory.store(passwd_addr, claripy.BVV(int.from_bytes(compared_str, "big"), password_size * 8))


@proj.hook(0x0804933e, length=5)
def is_equal(state):
    buffer = state.memory.load(buff_addr, buff_size)
    state.regs.eax = claripy.If(buffer == compared_str, claripy.BVV(1, 32), claripy.BVV(0, 32))


simgr = proj.factory.simulation_manager(init_state)
simgr.explore(find=0x08049343)


check_state = simgr.found[0]
check_state.add_constraints(check_state.regs.eax == 1)  # constraint for eval == 1
print("password0: {}".format(check_state.solver.eval(buffer, cast_to=bytes)))

# now we need to calculate the password's val after complex()
simgr2 = proj.factory.simgr(check_state)
simgr2.explore(find=0x08049393)  # last insn before second scanf()

check_state2 = simgr2.found[0]
password = check_state2.memory.load(passwd_addr, password_size)
print("password1: {}".format(check_state2.solver.eval(password, cast_to=bytes)))
