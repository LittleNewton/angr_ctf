import angr
import sys
import claripy


def find_path(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


bin_path = './03_angr_symbolic_registers.elf'
proj = angr.Project(bin_path)

# 这个地址要特别注意，不能是 _start 的地址
# 应该是 get_user_input 的地址，因为只有 get 之后
# 才能获得 eax, ebx, edx 的值，并将它们符号化

_start_addr = 0x0804945e
init_state = proj.factory.blank_state(addr=_start_addr)

# Create a symbolic variable for the input
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)
password2 = claripy.BVS('password2', 32)

init_state.regs.eax = password0
init_state.regs.ebx = password1
init_state.regs.edx = password2

simgr = proj.factory.simgr(init_state)
simgr.explore(find=find_path, avoid=avoid_path)


if simgr.found:
    solution_state = simgr.found[0]
    password0_value = solution_state.solver.eval(password0)
    password1_value = solution_state.solver.eval(password1)
    password2_value = solution_state.solver.eval(password2)

    print(f"Password 0: {hex(password0_value)}")
    print(f"Password 1: {hex(password1_value)}")
    print(f"Password 2: {hex(password2_value)}")

else:
    print("No solution found.")
